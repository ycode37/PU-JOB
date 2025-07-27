import express from "express";
import { login, register, logout, getCurrentUser } from "../controllers/authController.js";
import { upload } from "../Middlewares/multer.js";

const authRoute = express.Router();

authRoute.post("/signup", upload.single("image"), register);
authRoute.post("/login", login);
authRoute.get("/logout", logout);
authRoute.get("/me", getCurrentUser);

export default authRoute;
