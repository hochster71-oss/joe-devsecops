# Remove ELECTRON_RUN_AS_NODE to prevent Electron from running as Node
Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue

# Start electron-forge
npx electron-forge start
