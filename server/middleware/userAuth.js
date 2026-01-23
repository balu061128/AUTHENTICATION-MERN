import jwt from 'jsonwebtoken';

// Middleware to authenticate user using JWT from cookies
const userAuth = (req, res, next) => {
    try {
        const token = req.cookies?.token;

        // No token → not logged in
        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized access, login required"
            });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Attach userId to request
        req.userId = decoded.userId;

        // Continue to next middleware / controller
        next();

    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired token, login again"
        });
    }
};

export default userAuth;
