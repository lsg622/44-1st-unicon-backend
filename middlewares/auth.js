const jwt = require('jsonwebtoken');
const userService = require("../services/userService")

const loginRequired = async (req, res, next) => {
  // 1) Getting token and check of It's there
  const accessToken = req.headers.authorization;
  if (!accessToken) {
    const error = new Error('NEED_ACCESS_TOKEN');
    error.statusCode = 401;

    return res.status(error.statusCode).json({ message: error.message });
  }
  // 2) Verification token
  const decoded = await jwt.verify(accessToken, process.env.SECRET_KEY);

  // 3) Check if user still exists
  const user = await userService.getUserById(decoded.id);
  if (!user) {
    const error = new Error('USER_DOES_NOT_EXIST');
    error.statusCode = 404;

    return res.status(error.statusCode).json({ message: error.message });
  }
  // 4) Grant Access
  req.user = user;
  next();
};

module.exports = {
  loginRequired,
};
