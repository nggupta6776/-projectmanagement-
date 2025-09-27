// src/middlewares/auth.middleware.js

import { User } from "../models/user.models.js";
import { asyncHandler } from "../utils/async-handler.js";
import { ApiError } from "../utils/api-error.js";
import jwt from "jsonwebtoken";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken || // From cookies
    req.header("Authorization")?.replace("Bearer ", ""); // From headers

  if (!token) {
    throw new ApiError(401, "Unauthorized: Token missing");
  }

  try {
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

   
    const user = await User.findById(decodedToken?.id).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
    );

    if (!user) {
      throw new ApiError(401, "Invalid access token: user not found");
    }

    req.user = user; // Attach user to request
    next();
  } catch (error) {
    console.error("JWT verification error:", error.message); // Useful for debugging
    throw new ApiError(401, "Invalid access token");
  }
});
