require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");

const app = express();

app.use(express.json());

mongoose
  .set("strictQuery", true)
  .connect(process.env.MONGO_URI)
  .then(() => console.log("DB Connected"))
  .catch(err => console.log(err.message));

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  accessToken: {
    type: String,
  },
  accessTokenExpiry: {
    type: Date,
  },
});

const User = mongoose.model("User", userSchema);

function authenticateToken(req, res, next) {
  const accessToken = req.headers["x-access-token"];

  if (!accessToken) {
    return res.status(401).json({ message: "Access token missing" });
  }

  User.findOne({ accessToken, accessTokenExpiry: { $gt: Date.now() } })
    .then(user => {
      if (!user) {
        return res.status(401).json({ message: "Invalid access token" });
      }

      req.user = user;
      next();
    })
    .catch(err => {
      console.error("Failed to authenticate access token", err);
      res.status(500).json({ message: "Failed to authenticate access token" });
    });
}

app.post("/api/account/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Failed to register user", err);
    res.status(500).json({ message: "Failed to register user" });
  }
});

app.post("/api/account/session", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const accessToken = uuidv4();

    user.accessToken = accessToken;
    user.accessTokenExpiry = Date.now() + 3600000;

    await user.save();

    res.json({ accessToken });
  } catch (err) {
    console.error("Failed to login", err);
    res.status(500).json({ message: "Failed to login" });
  }
});

app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "Protected route accessed successfully" });
});

app.listen(3500, () => console.log("Server running"));
