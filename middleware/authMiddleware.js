const jwt = require('jsonwebtoken');

module.exports = function(req, res, next) {
  // 1. Get the token from the header
  const token = req.header('x-auth-token');

  // 2. Check if no token is found
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  // 3. Verify the token
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'a_default_secret_key');
    req.user = decoded.user; // Add the user payload to the request object
    next(); // Let the request proceed
  } catch (err) {
    console.error('TOKEN VERIFICATION FAILED:', err.name);
    res.status(401).json({ message: 'Token is not valid', errorName: err.name });
  }
};