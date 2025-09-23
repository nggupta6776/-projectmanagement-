import { Router } from "express";
import { healthCheck } from "../controllers/healthchek.controller.js";

const router = Router();

router.route("/").get(healthCheck);


export default router;