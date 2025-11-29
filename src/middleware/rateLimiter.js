
const rateLimit = require('express-rate-limit');

// Configuration for OTP Resend Limiter
const OtprateLimiter = rateLimit({
    windowMs: 300 * 1000, // 5 minute window (in milliseconds)
    max: 3, // Limit each IP to 3 requests per `windowMs`
    message: {
        success: false,
        message: "Too many requests send. Please try again after 5 minutes."
    },
    // Standard headers for rate limit info
    standardHeaders: true, 
    // Disable header that shows the use of the limiter
    legacyHeaders: false, 
});





// Configuration for Login Limiter
const LoginrateLimiter = rateLimit({
    windowMs: 300 * 1000, // 5 minute window (in milliseconds)
    max: 4, // Limit each IP to 4 requests per `windowMs`
    message: {
        success: false,
        message: "Too many requests send. Please try again after 5 minutes."
    },
    // Standard headers for rate limit info
    standardHeaders: true, 
    // Disable header that shows the use of the limiter
    legacyHeaders: false, 
});
module.exports = { OtprateLimiter, LoginrateLimiter };