import { Router } from "express";
import { login, logoutUser, registerUser } from "../controllers/auth.controller.js";
import { validator } from "../middlewares/validator.middleware.js";
import {userLoginValidator, userRegisterValidator } from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js"; 
const router = Router();

// Register route
router.route("/register").post(userRegisterValidator(), validator, registerUser);
router.route("/login").post(userLoginValidator(), validator , login);
//secure routes
router.route("/logout").post(verifyJWT, logoutUser);

export default router;
