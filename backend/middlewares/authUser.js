import jwt from 'jsonwebtoken';

// User authentication middleware
const authUser = async (req, res, next) => {
  try {
    // Extract token from headers
    const token = req.headers['token']; // Alternatively, use req.headers.authorization.split(' ')[1] if the token is prefixed with 'Bearer'
    if (!token) {
      return res.status(401).json({ success: false, message: 'Not Authorized. Please Login Again.' });
    }

    // Decode and verify token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    // Validate token payload (optional: customize based on your needs)
    if (!decodedToken || !decodedToken.email) {
      return res.status(401).json({ success: false, message: 'Invalid Token. Please Login Again.' });
    }

    // Attach decoded data to the request object
    req.user = decodedToken;

    next(); // Proceed to the next middleware
  } catch (error) {
    console.error('Error in authUser middleware:', error.message);
    res.status(500).json({ success: false, message: 'Internal Server Error', error: error.message });
  }
};

export default authUser;
