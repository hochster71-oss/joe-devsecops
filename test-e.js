const { app } = require("electron"); console.log("app:", typeof app); if (app) app.whenReady().then(() => { console.log("Ready\!"); app.quit(); });
