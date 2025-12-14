#!/usr/bin/env python3
"""
J.O.E. DevSecOps Arsenal - AutoFix Agent
Ollama-backed AI auto-remediation for CI failures

This agent:
1. Analyzes CI failure artifacts (logs, traces, screenshots)
2. Identifies the root cause
3. Generates a fix
4. Validates the fix passes all gates
5. Opens a PR if successful (never merges directly)

Requirements:
- Ollama running on OLLAMA_HOST with OLLAMA_MODEL available
- GitHub CLI (gh) authenticated
- All CI artifacts downloaded
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import requests

# Configuration from environment
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:latest")
GH_TOKEN = os.environ.get("GH_TOKEN", "")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "")
HEAD_SHA = os.environ.get("HEAD_SHA", "")
HEAD_BRANCH = os.environ.get("HEAD_BRANCH", "")

# Safety limits
MAX_FILES_TO_MODIFY = 5
MAX_LINES_PER_FILE = 100
FORBIDDEN_PATTERNS = [
    "rm -rf",
    "DROP TABLE",
    "eval(",
    "exec(",
    "__import__",
    "process.env",
    "secrets",
    ".env",
]


def log(message: str, level: str = "INFO") -> None:
    """Structured logging for CI visibility."""
    prefix = {"INFO": "ℹ️", "WARN": "⚠️", "ERROR": "❌", "SUCCESS": "✅"}.get(level, "")
    print(f"{prefix} [{level}] {message}", flush=True)


def run_command(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return result."""
    log(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def ollama_generate(prompt: str, system: Optional[str] = None) -> str:
    """Call Ollama API to generate a response."""
    url = f"{OLLAMA_HOST}/api/generate"
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 2048},
    }
    if system:
        payload["system"] = system

    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        return response.json().get("response", "")
    except requests.RequestException as e:
        log(f"Ollama request failed: {e}", "ERROR")
        return ""


def collect_failure_context() -> dict:
    """Collect all available failure context from CI artifacts."""
    context = {"logs": [], "traces": [], "screenshots": [], "errors": []}

    # Look for Playwright artifacts
    artifact_dirs = [
        Path("playwright-report"),
        Path("test-results"),
        Path("playwright-artifacts"),
    ]

    for artifact_dir in artifact_dirs:
        if artifact_dir.exists():
            # Collect error logs
            for log_file in artifact_dir.rglob("*.log"):
                try:
                    content = log_file.read_text(errors="ignore")[:5000]
                    context["logs"].append({"file": str(log_file), "content": content})
                except Exception:
                    pass

            # Collect trace files (just paths, too large to include)
            for trace_file in artifact_dir.rglob("*.zip"):
                context["traces"].append(str(trace_file))

            # Collect screenshot paths
            for screenshot in artifact_dir.rglob("*.png"):
                context["screenshots"].append(str(screenshot))

    # Look for npm/lint/typecheck errors in CI output
    ci_log = Path("ci-output.log")
    if ci_log.exists():
        context["logs"].append(
            {"file": "ci-output.log", "content": ci_log.read_text(errors="ignore")[:10000]}
        )

    return context


def analyze_failure(context: dict) -> dict:
    """Use Ollama to analyze the failure and identify root cause."""
    system_prompt = """You are an expert software engineer analyzing CI failures.
Your task is to identify:
1. The root cause of the failure
2. Which files need to be modified
3. What specific changes are needed

Be precise and conservative. Only suggest changes that directly address the failure.
Never suggest changes that could introduce security vulnerabilities.
Format your response as JSON."""

    prompt = f"""Analyze this CI failure and identify the fix needed.

Failure Context:
{json.dumps(context, indent=2)[:8000]}

Respond with JSON in this exact format:
{{
    "root_cause": "Brief description of why CI failed",
    "files_to_modify": [
        {{
            "path": "path/to/file.ts",
            "action": "edit|create",
            "changes": "Description of what to change"
        }}
    ],
    "confidence": "high|medium|low",
    "risk_assessment": "Description of any risks"
}}"""

    response = ollama_generate(prompt, system_prompt)

    try:
        # Extract JSON from response
        json_start = response.find("{")
        json_end = response.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            return json.loads(response[json_start:json_end])
    except json.JSONDecodeError:
        log("Failed to parse analysis response as JSON", "ERROR")

    return {"root_cause": "Unable to analyze", "files_to_modify": [], "confidence": "low"}


def generate_fix(analysis: dict) -> list[dict]:
    """Generate code fixes based on analysis."""
    fixes = []

    for file_info in analysis.get("files_to_modify", [])[:MAX_FILES_TO_MODIFY]:
        file_path = Path(file_info.get("path", ""))
        if not file_path.exists() and file_info.get("action") != "create":
            log(f"File not found: {file_path}", "WARN")
            continue

        # Read current content
        current_content = ""
        if file_path.exists():
            current_content = file_path.read_text(errors="ignore")

        system_prompt = """You are an expert software engineer fixing code.
Generate ONLY the fixed code, nothing else.
Preserve existing functionality.
Do not introduce security vulnerabilities.
Do not remove existing tests or safety checks."""

        prompt = f"""Fix the following file based on this analysis:

Analysis: {file_info.get('changes', '')}
Root cause: {analysis.get('root_cause', '')}

Current file content ({file_path}):
```
{current_content[:5000]}
```

Generate the complete fixed file content. Output ONLY the code, no explanations."""

        fixed_content = ollama_generate(prompt, system_prompt)

        # Clean up response (remove markdown code blocks if present)
        if fixed_content.startswith("```"):
            lines = fixed_content.split("\n")
            fixed_content = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        # Safety check
        if len(fixed_content.split("\n")) > MAX_LINES_PER_FILE + len(
            current_content.split("\n")
        ):
            log(f"Fix for {file_path} exceeds line limit, skipping", "WARN")
            continue

        for pattern in FORBIDDEN_PATTERNS:
            if pattern in fixed_content and pattern not in current_content:
                log(f"Fix contains forbidden pattern '{pattern}', skipping", "WARN")
                continue

        if fixed_content and fixed_content != current_content:
            fixes.append(
                {"path": str(file_path), "original": current_content, "fixed": fixed_content}
            )

    return fixes


def apply_fixes(fixes: list[dict]) -> bool:
    """Apply fixes to files."""
    for fix in fixes:
        file_path = Path(fix["path"])
        log(f"Applying fix to {file_path}")

        # Backup original
        backup_path = file_path.with_suffix(file_path.suffix + ".backup")
        if file_path.exists():
            backup_path.write_text(fix["original"])

        # Write fix
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(fix["fixed"])

    return len(fixes) > 0


def verify_fix() -> bool:
    """Run all gates to verify the fix works."""
    log("Verifying fix passes all gates...")

    gates = [
        ["npm", "run", "lint"],
        ["npm", "run", "typecheck"],
        ["npm", "test", "--if-present"],
        ["npm", "run", "qa:testid-coverage"],
        ["npm", "audit"],
    ]

    for gate in gates:
        try:
            result = run_command(gate, check=False)
            if result.returncode != 0:
                log(f"Gate failed: {' '.join(gate)}", "ERROR")
                log(f"Output: {result.stdout[:1000]}", "ERROR")
                log(f"Error: {result.stderr[:1000]}", "ERROR")
                return False
            log(f"Gate passed: {' '.join(gate)}", "SUCCESS")
        except Exception as e:
            log(f"Gate execution failed: {e}", "ERROR")
            return False

    return True


def create_fix_pr(fixes: list[dict], analysis: dict) -> bool:
    """Create a PR with the fix."""
    if not GH_TOKEN or not GITHUB_REPOSITORY:
        log("GitHub credentials not configured, skipping PR creation", "WARN")
        return False

    branch_name = f"autofix/{HEAD_SHA[:8]}"

    try:
        # Create branch
        run_command(["git", "checkout", "-b", branch_name])

        # Stage changes
        for fix in fixes:
            run_command(["git", "add", fix["path"]])

        # Commit
        commit_message = f"""fix: Auto-remediation for CI failure

Root cause: {analysis.get('root_cause', 'Unknown')}

Files modified:
{chr(10).join('- ' + fix['path'] for fix in fixes)}

🤖 Generated by J.O.E. AutoFix Agent
Verified: All gates passed before PR creation

Co-Authored-By: J.O.E. AutoFix <autofix@darkwolf.io>
"""
        run_command(["git", "commit", "-m", commit_message])

        # Push
        run_command(["git", "push", "-u", "origin", branch_name])

        # Create PR
        pr_body = f"""## Auto-Remediation PR

### Root Cause
{analysis.get('root_cause', 'Unknown')}

### Risk Assessment
{analysis.get('risk_assessment', 'Not assessed')}

### Confidence Level
{analysis.get('confidence', 'Unknown')}

### Files Modified
{chr(10).join('- `' + fix['path'] + '`' for fix in fixes)}

### Verification
All CI gates passed:
- ✅ Lint
- ✅ Typecheck
- ✅ Unit tests
- ✅ TestID coverage
- ✅ npm audit

---
🤖 Generated by J.O.E. AutoFix Agent
"""
        result = run_command(
            [
                "gh",
                "pr",
                "create",
                "--title",
                f"fix: Auto-remediation for {HEAD_BRANCH}",
                "--body",
                pr_body,
                "--base",
                HEAD_BRANCH,
            ],
            check=False,
        )

        if result.returncode == 0:
            log(f"PR created successfully: {result.stdout.strip()}", "SUCCESS")
            return True
        else:
            log(f"PR creation failed: {result.stderr}", "ERROR")
            return False

    except Exception as e:
        log(f"PR creation failed: {e}", "ERROR")
        return False


def rollback_fixes(fixes: list[dict]) -> None:
    """Rollback fixes if verification fails."""
    log("Rolling back fixes...")
    for fix in fixes:
        file_path = Path(fix["path"])
        backup_path = file_path.with_suffix(file_path.suffix + ".backup")

        if backup_path.exists():
            backup_path.rename(file_path)
            log(f"Rolled back {file_path}")
        elif fix.get("original"):
            file_path.write_text(fix["original"])
            log(f"Restored {file_path}")


def main() -> int:
    """Main entry point."""
    log("=" * 60)
    log("J.O.E. AutoFix Agent Starting")
    log(f"Model: {OLLAMA_MODEL}")
    log(f"Target commit: {HEAD_SHA}")
    log(f"Target branch: {HEAD_BRANCH}")
    log("=" * 60)

    # Step 1: Check Ollama connectivity
    try:
        response = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        if response.status_code != 200:
            log("Ollama not reachable", "ERROR")
            return 1
        log("Ollama connected", "SUCCESS")
    except requests.RequestException:
        log(f"Cannot connect to Ollama at {OLLAMA_HOST}", "ERROR")
        return 1

    # Step 2: Collect failure context
    log("Collecting failure context...")
    context = collect_failure_context()
    log(
        f"Found {len(context['logs'])} logs, {len(context['traces'])} traces, "
        f"{len(context['screenshots'])} screenshots"
    )

    if not context["logs"] and not context["traces"]:
        log("No failure context found, cannot proceed", "ERROR")
        return 1

    # Step 3: Analyze failure
    log("Analyzing failure with AI...")
    analysis = analyze_failure(context)
    log(f"Root cause: {analysis.get('root_cause', 'Unknown')}")
    log(f"Confidence: {analysis.get('confidence', 'Unknown')}")

    if analysis.get("confidence") == "low":
        log("Low confidence analysis, aborting to avoid incorrect fixes", "WARN")
        return 1

    if not analysis.get("files_to_modify"):
        log("No files identified for modification", "WARN")
        return 1

    # Step 4: Generate fixes
    log("Generating fixes...")
    fixes = generate_fix(analysis)

    if not fixes:
        log("No valid fixes generated", "WARN")
        return 1

    log(f"Generated {len(fixes)} fixes")

    # Step 5: Apply fixes
    if not apply_fixes(fixes):
        log("Failed to apply fixes", "ERROR")
        return 1

    # Step 6: Verify fixes pass all gates
    if not verify_fix():
        log("Fix verification failed, rolling back", "ERROR")
        rollback_fixes(fixes)
        return 1

    log("Fix verified - all gates pass!", "SUCCESS")

    # Step 7: Create PR (never merge directly)
    if create_fix_pr(fixes, analysis):
        log("AutoFix complete - PR created for review", "SUCCESS")
        return 0
    else:
        log("PR creation failed, but fixes are valid", "WARN")
        return 1


if __name__ == "__main__":
    sys.exit(main())
