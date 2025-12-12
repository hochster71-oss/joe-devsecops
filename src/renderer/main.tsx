import React from 'react';
import ReactDOM from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import App from './App';
import './styles/globals.css';

// Using HashRouter instead of BrowserRouter for Electron compatibility
// BrowserRouter uses browser history API which requires HTTP URLs
// Electron uses file:// protocol, so HashRouter (uses URL hash) is required
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <HashRouter>
      <App />
    </HashRouter>
  </React.StrictMode>
);
