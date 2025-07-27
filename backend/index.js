import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { connectDB } from "./config/connectDB.js";
import authRoute from "./Routes/authRoute.js";
import useRouter from "./Routes/userRoute.js";

dotenv.config();

const app = express();

const allowedOriginals = ["http://localhost:5173"];

// MiddleWare
app.use(express.json());
app.use(cors({ origin: allowedOriginals, credentials: true }));
app.use(cookieParser());

//DB connected
connectDB();
//Api Endpoints
app.get("/", (req, res) => {
  res.send("Hello");
});
app.get("/uploads", express.static("uploads"));
app.use("/auth", authRoute);
app.use("/user", useRouter);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`server is currently running under ${PORT}`);
});
