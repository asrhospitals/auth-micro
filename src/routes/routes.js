const express = require("express");
const {
  login,
  verifyOtp,
  resendOtp,
  createUser,
  assignRole,
  getAllUsers,
  searchUsers,
  getUserById,
  updateUsers,
  logout,
  selectRole,
} = require("../controller/authenticationController");
const { getMySessionLogs, getAllSessionLogs } = require("../controller/sessionController");
const { authenticateToken, checkAdminRole } = require("../middleware/authMiddileware");
const { LoginrateLimiter, OtprateLimiter } = require("../middleware/rateLimiter");


// Use express.Router() explicitly
const router = express.Router(); 

// --- Authentication & Public Routes ---
// Typically prefixed with /auth/ for clarity
router.post("/auth/signup",authenticateToken, createUser); 
router.post("/auth/login",login); 
router.post("/auth/verify-otp", verifyOtp); // Kebab-case for URL
router.post("/auth/resend-otp/:userId", resendOtp); // Kebab-case and camelCase for param
router.post("/auth/logout",authenticateToken, logout); // Logout route
router.post("/auth/generate-token", selectRole); // Generate token after role selection

// --- User Resource Routes (RESTful CRUD) ---
// Base route for the user collection: /users

router.route("/users")
  .get(getAllUsers); // GET /users to retrieve all users

// Use query parameters (e.g., /users?q=...) for searching 
// or define a clear search endpoint
router.get("/users/search", searchUsers); // GET /users/search

// Special actions on the user collection
router.put("/users/assign-role",authenticateToken ,assignRole); // PUT /users/assign-role

// Routes targeting a specific user resource: /users/:id
router.route("/users/:id")
  .get(getUserById)    // GET /users/:id to retrieve one user
  .put(updateUsers);   // PUT /users/:id to update one user
  

/**
 * @route GET /lims/api/sessions/my-logs
 * @description User sees their own log history. Requires standard user token.
 */
router.get('/my-logs',authenticateToken, getMySessionLogs);


/**
 * @route GET /lims/api/sessions/all-logs
 * @description Admin retrieves all log history (paginated). Requires Admin role.
 */
router.get('/all-logs',authenticateToken,checkAdminRole,getAllSessionLogs);

module.exports = router;