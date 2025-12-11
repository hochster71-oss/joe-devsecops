import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Users,
  UserPlus,
  Shield,
  User,
  Trash2,
  Edit,
  Key,
  Check,
  X
} from 'lucide-react';

interface UserAccount {
  id: string;
  username: string;
  displayName: string;
  email: string;
  role: 'administrator' | 'standard';
  lastLogin: string;
  status: 'active' | 'inactive';
}

const mockUsers: UserAccount[] = [
  {
    id: '1',
    username: 'mhoch',
    displayName: 'Michael Hoch',
    email: 'michael@darkwolfsolutions.com',
    role: 'administrator',
    lastLogin: '2024-12-10 10:30 AM',
    status: 'active'
  },
  {
    id: '2',
    username: 'jscholer',
    displayName: 'Joseph Scholer',
    email: 'joseph@darkwolfsolutions.com',
    role: 'standard',
    lastLogin: '2024-12-09 3:45 PM',
    status: 'active'
  }
];

export default function AdminView() {
  const [users, setUsers] = useState<UserAccount[]>(mockUsers);
  const [showAddUser, setShowAddUser] = useState(false);
  const [newUser, setNewUser] = useState({
    username: '',
    displayName: '',
    email: '',
    role: 'standard' as 'administrator' | 'standard',
    password: ''
  });

  const handleAddUser = () => {
    if (!newUser.username || !newUser.displayName || !newUser.password) return;

    const user: UserAccount = {
      id: Date.now().toString(),
      username: newUser.username,
      displayName: newUser.displayName,
      email: newUser.email,
      role: newUser.role,
      lastLogin: 'Never',
      status: 'active'
    };

    setUsers([...users, user]);
    setShowAddUser(false);
    setNewUser({ username: '', displayName: '', email: '', role: 'standard', password: '' });
  };

  const handleDeleteUser = (id: string) => {
    if (users.length <= 1) return; // Keep at least one admin
    setUsers(users.filter(u => u.id !== id));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-2xl font-bold text-white">User Management</h1>
          <p className="text-gray-400 mt-1">Manage users and access control</p>
        </div>
        <button
          onClick={() => setShowAddUser(true)}
          className="btn-primary flex items-center gap-2"
        >
          <UserPlus size={16} />
          Add User
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="glass-card p-4 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-joe-blue/10">
            <Users className="text-joe-blue" size={24} />
          </div>
          <div>
            <p className="text-2xl font-bold text-white">{users.length}</p>
            <p className="text-gray-400 text-sm">Total Users</p>
          </div>
        </div>
        <div className="glass-card p-4 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-alert-warning/10">
            <Shield className="text-alert-warning" size={24} />
          </div>
          <div>
            <p className="text-2xl font-bold text-white">
              {users.filter(u => u.role === 'administrator').length}
            </p>
            <p className="text-gray-400 text-sm">Administrators</p>
          </div>
        </div>
        <div className="glass-card p-4 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-dws-green/10">
            <User className="text-dws-green" size={24} />
          </div>
          <div>
            <p className="text-2xl font-bold text-white">
              {users.filter(u => u.role === 'standard').length}
            </p>
            <p className="text-gray-400 text-sm">Standard Users</p>
          </div>
        </div>
      </div>

      {/* Add User Modal */}
      {showAddUser && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => setShowAddUser(false)}
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="glass-card p-6 w-full max-w-md"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="font-heading font-semibold text-white text-lg mb-4">Add New User</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-2">Username</label>
                <input
                  type="text"
                  value={newUser.username}
                  onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                  className="input-field"
                  placeholder="Enter username"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">Display Name</label>
                <input
                  type="text"
                  value={newUser.displayName}
                  onChange={(e) => setNewUser({ ...newUser, displayName: e.target.value })}
                  className="input-field"
                  placeholder="Enter full name"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">Email</label>
                <input
                  type="email"
                  value={newUser.email}
                  onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                  className="input-field"
                  placeholder="Enter email"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">Password</label>
                <input
                  type="password"
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  className="input-field"
                  placeholder="Enter password"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">Role</label>
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({ ...newUser, role: e.target.value as 'administrator' | 'standard' })}
                  className="input-field"
                >
                  <option value="standard">Standard User</option>
                  <option value="administrator">Administrator</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 mt-6">
              <button
                onClick={() => setShowAddUser(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
              <button onClick={handleAddUser} className="btn-primary">
                Add User
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}

      {/* Users Table */}
      <div className="glass-card overflow-hidden">
        <table className="w-full">
          <thead className="bg-dws-card/50">
            <tr className="text-left text-sm text-gray-400">
              <th className="p-4">User</th>
              <th className="p-4">Role</th>
              <th className="p-4">Status</th>
              <th className="p-4">Last Login</th>
              <th className="p-4">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user, index) => (
              <motion.tr
                key={user.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: index * 0.05 }}
                className="border-t border-dws-border hover:bg-dws-card/30 transition-colors"
              >
                <td className="p-4">
                  <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                      user.role === 'administrator' ? 'bg-joe-blue/20' : 'bg-dws-green/20'
                    }`}>
                      {user.role === 'administrator' ? (
                        <Shield size={18} className="text-joe-blue" />
                      ) : (
                        <User size={18} className="text-dws-green" />
                      )}
                    </div>
                    <div>
                      <p className="text-white font-medium">{user.displayName}</p>
                      <p className="text-gray-500 text-sm">@{user.username}</p>
                    </div>
                  </div>
                </td>
                <td className="p-4">
                  <span className={`badge ${
                    user.role === 'administrator' ? 'badge-info' : 'badge-low'
                  } capitalize`}>
                    {user.role}
                  </span>
                </td>
                <td className="p-4">
                  <span className={`badge ${
                    user.status === 'active' ? 'badge-low' : 'badge-medium'
                  } capitalize`}>
                    {user.status}
                  </span>
                </td>
                <td className="p-4 text-gray-400 text-sm">{user.lastLogin}</td>
                <td className="p-4">
                  <div className="flex items-center gap-2">
                    <button className="p-2 hover:bg-dws-card rounded transition-colors" title="Edit">
                      <Edit size={16} className="text-gray-400" />
                    </button>
                    <button className="p-2 hover:bg-dws-card rounded transition-colors" title="Reset Password">
                      <Key size={16} className="text-joe-blue" />
                    </button>
                    <button
                      onClick={() => handleDeleteUser(user.id)}
                      className="p-2 hover:bg-dws-card rounded transition-colors"
                      title="Delete"
                      disabled={users.length <= 1}
                    >
                      <Trash2 size={16} className={users.length <= 1 ? 'text-gray-600' : 'text-alert-critical'} />
                    </button>
                  </div>
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
