// Application Configuration
const CONFIG = {
    apiEndpoint: '/api',
    apiKey: 'api_key_1234567890',
    adminSecret: 'admin_secret_key',
    debugMode: true,
    // FLAG: FLAG{J4v4Scr1pt_S0urc3_3xp0s3d}
};

// Development notes - Remove in production
// Admin credentials: admin/password123
// Database: SQLite (icss_ctf.db)
// Hidden endpoints: /admin, /api/users, /debug/error
// Backup directory: /backup/

// JWT Secret for testing: jwt_secret_123
// Session Secret: super_secret_key_12345

// API Endpoints:
// - GET /api/users - List all users (no auth required!)
// - GET /api/course/{id} - Get course details
// - POST /api/login - Generate JWT token
// - GET /api/admin/secret - Admin endpoint (JWT required)

console.log('ICSS Application Config Loaded');

// Hidden functionality - for internal use only
function getAdminFlag() {
    return 'FLAG{J4v4Scr1pt_S0urc3_3xp0s3d}';
}
