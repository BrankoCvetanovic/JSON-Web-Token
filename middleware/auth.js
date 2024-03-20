const jwt = require("jsonwebtoken");
const CustomAPIError = require("../errors/custom-error");

async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new CustomAPIError("There is no token provided", 401);
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { id, username } = decoded;
    req.user = { id, username };
  } catch (error) {
    throw new CustomAPIError("Not authorized to access this route", 401);
  }
  next();
}

module.exports = authMiddleware;
