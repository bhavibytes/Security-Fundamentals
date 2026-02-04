const authMiddleware = (req, res, next) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ 
      error: 'Unauthorized',
      message: 'Please login to access this resource'
    });
  }
  
  req.user = req.session.user;
  next();
};

module.exports = authMiddleware;
