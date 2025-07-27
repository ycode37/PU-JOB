import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import User from "../models/userModel.js";

//Register A User

export const register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
      return res.json({ success: false, message: "All fields are required" });
    }

    // Handle optional file upload
    const image = req.file ? req.file.filename : "";

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role,
      image,
    });
    return res.json({ success: true, message: "User Added Successfully" });
  } catch (error) {
    console.log(error);
    return res.json({ success: false, message: "Internal Server Error" });
  }
};

//login User

export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    if (
      email === process.env.ADMIN_EMAIL &&
      password === process.env.ADMIN_PASSWORD
    ) {
      const token = jwt.sign(
        { email: process.env.ADMIN_EMAIL },
        process.env.JWT_SECRET_KEY,
        { expiresIn: "1d" }
      );
      if (
        email === process.env.ADMIN_EMAIL &&
        password === process.env.ADMIN_PASSWORD
      ) {
        const token = jwt.sign(
          { email: process.env.ADMIN_EMAIL, role: "admin" }, // Added role to token
          process.env.JWT_SECRET_KEY,
          { expiresIn: "1d" }
        );
        // Send only ONE response
        return res
          .cookie("token", token, {
            httpOnly: true,
            maxAge: 3600000,
            secure: true,
            sameSite: "none",
            domain: "onrender.com",
          })
          .json({
            success: true,
            message: "Admin Login Successful",
            user: { email: process.env.ADMIN_EMAIL, role: "admin" }, // The user object is now included
          });
      }
    }
    //user login
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User Not Found" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ success: false, message: "Invalid Credentials" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: "1d",
    });
    // ...

    // Correct way to set the cookie with all options
    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 3600000,
      secure: true,
      sameSite: "none",
      domain: "onrender.com",
    });
    return res.json({
      success: true,
      message: "User Logged In Successfully",
      user,
    });
    //...
  } catch (error) {
    return res.json({ success: false, message: "Internal Server Error" });
  }
};

// logout
export const logout = async (req, res) => {
  res.clearCookie("token");
  return res.json({ success: true, message: "LogOut Successful" });
};

// Get current user
export const getCurrentUser = async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ success: false, message: "No token" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "User not found" });
    }

    res.json({ success: true, user });
  } catch (err) {
    res.status(401).json({ success: false, message: "Invalid token" });
  }
};

