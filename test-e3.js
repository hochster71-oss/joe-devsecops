console.log("Testing process.type:", process.type);
console.log("process.versions.electron:", process.versions.electron);

// Try to access electron through process
if (process.type === 'browser') {
  // We're in main process - try different ways to get electron
  console.log("In main process");
  
  // Try using a different module name
  try {
    const { app, BrowserWindow } = require('electron/main');
    console.log("electron/main worked:", typeof app);
  } catch (e) {
    console.log("electron/main failed:", e.message);
  }
  
  // Try global electron
  try {
    console.log("global.electron:", typeof global.electron);
  } catch (e) {
    console.log("global.electron failed:", e.message);
  }
}
