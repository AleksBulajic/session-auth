import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose from "mongoose";
import methodOverride from "method-override";
import morgan from "morgan";

const app = express();

// Set the port from environment variable or default to 3000
const port = process.env.PORT || "3000";

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

app.listen(port, () => {
  console.log(`The express app is ready on port ${port}!`);
});
