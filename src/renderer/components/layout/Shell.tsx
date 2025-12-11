import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import StatusBar from './StatusBar';

export default function Shell() {
  return (
    <div className="h-screen w-screen flex flex-col bg-dws-darker overflow-hidden">
      {/* Custom Title Bar */}
      <Header />

      {/* Main Content Area */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar Navigation */}
        <Sidebar />

        {/* Main Content */}
        <main className="flex-1 overflow-auto p-6 bg-dws-dark/50">
          <Outlet />
        </main>
      </div>

      {/* Status Bar */}
      <StatusBar />
    </div>
  );
}
