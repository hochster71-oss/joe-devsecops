console.log("Script running...");
console.log("process.type:", process.type);
console.log("process.versions.electron:", process.versions.electron);

// Delete the require cache for electron to force re-resolution
delete require.cache[require.resolve('electron')];

// Now try requiring from a path that doesn't exist in node_modules
const Module = require('module');
const originalResolve = Module._resolveFilename;
Module._resolveFilename = function(request, parent, isMain, options) {
  if (request === 'electron') {
    // Return a special path that forces the built-in module
    console.log("Intercepting electron require...");
  }
  return originalResolve(request, parent, isMain, options);
};

const electron = require('electron');
console.log("electron type:", typeof electron);
