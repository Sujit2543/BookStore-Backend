// --- server.js ---
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// --- MongoDB Connection ---
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => console.error("❌ MongoDB connection failed:", err));

// --- User Schema ---
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  secondName: { type: String },
  lastName: { type: String },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetToken: { type: String },
  resetTokenExpiry: { type: Date },
});

const User = mongoose.model("User", userSchema);

app.get('/', (req,res)=>{
  res.send("HOME");
})

// --- Register API ---
app.post("/register", async (req, res) => {
  try {
    const { firstName, secondName, lastName, email, password } = req.body;

    if (!firstName || !email || !password) {
      return res.status(400).json({ message: "All required fields must be filled" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      firstName,
      secondName,
      lastName,
      email,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- Login API ---
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Email and password are required" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: "User not found" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.status(200).json({
      message: "Login successful",
      token,
      redirectTo: "/home",
    });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- Forgot Password API ---
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: "No user found with that email." });

    // Generate reset token
    const token = crypto.randomBytes(32).toString("hex");
    user.resetToken = token;
    user.resetTokenExpiry = Date.now() + 3600000; // valid for 1 hour
    await user.save();

    // Configure email transport
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER, // use environment variables
        pass: process.env.EMAIL_PASS,
      },
    });

    const resetLink = `http://localhost:3000/reset-password/${token}`;

    await transporter.sendMail({
      to: email,
      subject: "Password Reset Request - BookPoint",
      html: `
        <p>Hello ${user.firstName || "User"},</p>
        <p>You requested to reset your password. Click the link below to set a new one:</p>
        <a href="${resetLink}" target="_blank">${resetLink}</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn’t request this, please ignore this email.</p>
      `,
    });

    res.json({ message: "✅ Password reset link sent successfully to your email." });
  } catch (err) {
    console.error("Error in forgot-password:", err);
    res.status(500).json({ message: "Error sending reset email." });
  }
});

// --- Reset Password API ---
app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }, // token still valid
    });

    if (!user)
      return res.status(400).json({ message: "Invalid or expired reset token." });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;

    await user.save();
    res.json({ message: "✅ Password has been reset successfully." });
  } catch (err) {
    console.error("Error in reset-password:", err);
    res.status(500).json({ message: "Server error resetting password." });
  }
});

// --- Middleware: Verify JWT ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader)
    return res.status(403).json({ message: "Token required" });

    const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err)
      return res.status(403).json({ message: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
};

// --- Protected Route ---
app.get("/home", verifyToken, (req, res) => {
  res.json({
    message: "Welcome to BookPoint Home!",
    user: req.user,
  });
});

// // --- Start Server ---
// const PORT = process.env.PORT || 5000;
// app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

module.exports = app;