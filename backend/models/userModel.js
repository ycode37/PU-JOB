import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ["student", "employer", "admin"],
      required: true,
    },
    image: {
      type: String,
      default: "",
    },
    about: {
      type: String,
      default: "",
    },
    phone: {
      type: String,
      default: "",
    },
    resume: {
      type: String,
      default: "",
    },
    education: {
      type: String,
      default: "Not specified",
    },
    experience: {
      type: String,
      default: "Not specified",
    },
    skills: {
      type: String,
      default: "Not specified",
    },
    location: {
      type: String,
      default: "",
    },
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model("User", userSchema);
export default User;
