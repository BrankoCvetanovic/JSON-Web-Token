const jwt = require("jsonwebtoken");
const CustomAPIError = require("../errors/custom-error");

async function login(req, res) {
  const { username, password } = req.body;

  if (!username || !password) {
    throw new CustomAPIError("Please provide username and password", 400);
  }
  const id = new Date().getDate();
  const token = jwt.sign({ id, username }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });

  res.status(200).json({ msg: "user created", token });
}

async function dashboard(req, res) {
  const luckyNumber = Math.floor(Math.random() * 100);
  res.status(200).json({
    msg: `Hello, ${req.user.username}`,
    secret: `Here is your authorized data, your lucky number: ${luckyNumber}`,
  });
}

module.exports = { login, dashboard };
