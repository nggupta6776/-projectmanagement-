import { Router } from "express";
import { login, registerUser } from "../controllers/auth.controller.js";
import { validator } from "../middlewares/validator.middleware.js";
import {userLoginValidator, userRegisterValidator } from "../validators/index.js";

const router = Router();

// Register route
router.route("/register").post(userRegisterValidator(), validator, registerUser);
router.route("/login").post(userLoginValidator(), validator , login);

export default router;
