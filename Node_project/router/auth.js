import express from "express";
import { protect } from "../middleware/auth.js";
import {
  registerUser,
  loginUser,
  logout,
  getMe,
  forgotPassword,
  updateDetails,
  updatePassword,
  resetPassword,
} from "../controllers/auth.controller.js";

const authRouter = express.Router();

authRouter.post("/register", registerUser);//
authRouter.post("/login", loginUser);//
authRouter.get("/logout", logout);//
authRouter.get("/me", protect, getMe);//
authRouter.post("/forgotpassword", protect, forgotPassword);
authRouter.put("/updatedetails", protect, updateDetails);
authRouter.put("/updatepassword", protect, updatePassword);
authRouter.put("/forgotpassword/:resetpassword", resetPassword);

export default authRouter;
