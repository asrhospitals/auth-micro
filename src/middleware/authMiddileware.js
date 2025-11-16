const jwt = require('jsonwebtoken');


// The name of the environment variable holding your JWT secret key
const JWT_SECRET = process.env.JWT_SECRET; 

/**
 * Middleware to verify the JWT token and attach user data to the request.
 * The decoded token payload (e.g., { userid, role, roleType, ... }) is stored in req.user.
 * * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Next middleware function
 */
const authenticateToken = (req, res, next) => {
    // 1. Check for token in the Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract token from "Bearer TOKEN"

    if (!token) {
        console.warn('Authentication attempt failed: No token provided.');
        return res.status(401).json({ 
            message: "Access Denied. Token is required.",
            error: "UNAUTHORIZED_NO_TOKEN" 
        });
    }

    // 2. Verify the token
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Token verification failed:', err.message);
            return res.status(403).json({ 
                message: "Invalid Token. Access Forbidden.",
                error: "FORBIDDEN_INVALID_TOKEN" 
            });
        }
        
        // 3. Token is valid. Attach decoded user payload to request.
        // The payload usually contains { userid, role, roleType, ... }
        req.user = user; 
        
        next();
    });
};




/**
 * Middleware to check if the authenticated user has the 'admin' role type.
 * Requires authenticateToken to run first.
 * * @param {object} req - Express request object (must contain req.user)
 * @param {object} res - Express response object
 * @param {function} next - Next middleware function
 */
const checkAdminRole = async (req, res, next) => {
    // Safely retrieve and normalize the roleType from the token payload (req.user)
    // Using optional chaining (?. ) prevents crashing if req.user or req.user.roleType is undefined.
    // This is the core fix for the "Cannot read properties of undefined (reading 'roleType')" error.
    const roleType = req.user?.roleType?.toLowerCase(); 

    if (!roleType) {
        // If req.user is missing OR req.user.roleType is missing
        return res.status(403).json({ 
            message: "Authorization Failed. User role information is missing or token is invalid.",
            error: "FORBIDDEN_ROLE_MISSING"
        });
    }

    console.log(roleType);
    
    
    if (roleType === 'admin') {
        next();
    } else {
        return res.status(403).json({
            message: "Access Denied. Only administrators can view all session logs.",
            error: "FORBIDDEN_INSUFFICIENT_PRIVILEGES"
        });
    }
};


module.exports={authenticateToken,checkAdminRole};

