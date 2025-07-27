import express from "express";
import { isAuthenticated } from "../Middlewares/isAuthenticated.js";
import {
  getLoggedInUser,
  updateProfile,
} from "../controllers/userController.js";

const useRouter = express.Router();

useRouter.get("/me", isAuthenticated, getLoggedInUser);
useRouter.put("/update-profile/:id", isAuthenticated, updateProfile);
useRouter.put("all-students", isAuthenticated, updateProfile);

export default useRouter;
