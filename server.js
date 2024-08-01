import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose from "mongoose";
import methodOverride from "method-override";
import morgan from "morgan";
import session from "express-session";

// controllers imports
import authController from "./controllers/auth.js";

const app = express();

// Set the port from environment variable or default to 3000
const port = process.env.PORT;

mongoose.connect(process.env.MONGODB_URI);

mongoose.connection.on("connected", () => {
  console.log(`Connected to MongoDB ${mongoose.connection.name}.`);
});

// Middleware to parse URL-encoded data from forms
app.use(express.urlencoded({ extended: false }));
// Middleware for using HTTP verbs such as PUT or DELETE
app.use(methodOverride("_method"));
// Morgan for logging HTTP requests
app.use(morgan("dev"));
//express-session
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

// GET
app.get("/", async (req, res) => {
  res.render("index.ejs", {
    user: req.session.user,
  });
});

app.get("/vip-lounge", (req, res) => {
  if (req.session.user) {
    res.send(`Welcome to the party ${req.session.user.username}.`);
  } else {
    res.send("Sorry, no guests allowed.");
  }
});

//auth routes
app.use("/auth", authController);

app.listen(port, () => {
  console.log(`The express app is ready on port ${port}!`);
});
