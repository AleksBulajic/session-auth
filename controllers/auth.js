import express from "express";
import User from "../models/users.js";
import bcrypt from "bcrypt";

const authRouter = express.Router();

authRouter.get("/sign-up", async (req, res) => {
  res.render("auth/sign-up.ejs");
});

authRouter.get("/sign-in", (req, res) => {
  res.render("auth/sign-in.ejs");
});

authRouter.post("/sign-up", async (req, res) => {
  const userInDatabase = await User.findOne({ username: req.body.username });
  if (userInDatabase) {
    return res.send("Username already taken.");
  }

  if (req.body.password !== req.body.confirmPassword) {
    return res.send("Password and Confirm Password must match");
  }
  const hashedPassword = bcrypt.hashSync(req.body.password, 10);
  req.body.password = hashedPassword;

  const user = await User.create(req.body);
  res.send(`Thanks for signing up ${user.username}`);
});

authRouter.post("/sign-in", async (req, res) => {
  try {
    const userInDatabase = await User.findOne({ username: req.body.username });
    if (!userInDatabase) {
      return res.send("Login failed. Please try again.");
    }
    //compare provided raw password with the hased password
const validPassword = bcrypt.compareSync(
    req.body.password,
    userInDatabase.password
)
if (!validPassword) {
    return res.send("Login failed. Please try again.");
  }
  } catch (error) {
    console.error("was not able to sign in", error);
  }
});
export default authRouter;
