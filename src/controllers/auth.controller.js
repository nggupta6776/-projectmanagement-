import { User } from "../models/user.models.js";
import { APIResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";
import { StatusCodes } from "http-status-codes";
import crypto from "crypto";
import jwt  from "jsonwebtoken";

// ------------------ TOKEN GENERATION ------------------
const generateAccessTokenAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            "Something went wrong while generating access tokens"
        );
    }
};

// ------------------ REGISTER ------------------
const registerUser = asyncHandler(async (req, res) => {
    const { email, username, password, role } = req.body;

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    });

    if (existedUser) {
        throw new ApiError(
            StatusCodes.CONFLICT,
            "User with email or username already exists",
            []
        );
    }

    const user = await User.create({
        email,
        password,
        username,
        isEmailVerified: false
    });

    const { unHashedToken, hashedToken, tokenExpiry } =
        user.generateTemporaryToken();

    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    await sendEmail({
        email: user?.email,
        subject: "Please verify your email",
        mailgenContent: emailVerificationMailgenContent(
            user.username,
            `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
        ),
    });

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
    );

    if (!createdUser) {
        throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            "Something went wrong while registering a user"
        );
    }

    return res.status(StatusCodes.CREATED).json(
        new APIResponse(
            StatusCodes.CREATED,
            { user: createdUser },
            "User registered successfully and verification email has been sent."
        )
    );
});

// ------------------ LOGIN ------------------
const login = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) throw new ApiError(400, "User does not exist");

    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) throw new ApiError(400, "Invalid credentials");

    const { accessToken, refreshToken } = await generateAccessTokenAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken -emailVerificationExpiry"
    );

    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
    };

    return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new APIResponse(
                200,
                { user: loggedInUser, accessToken, refreshToken },
                "User logged in successfully"
            )
        );
});

// ------------------ LOGOUT ------------------
const logoutUser = asyncHandler(async (req, res)=> {
    await User.findByIdAndUpdate(
        req.user._id,
        { $set: { refreshToken: "" } },
        { new: true }
    );

    const options = { httpOnly: true, secure: true };

    return res.status(200)
        .clearCookie("refreshToken", options)
        .json(new APIResponse(200, {}, "User logged out"));
});

// ------------------ GET CURRENT USER ------------------
const getCurrentUser = asyncHandler (async (req, res) => {  
    return res.status(200).json(
        new APIResponse(
            200,
            req.user,
            "Current user fetched successfully"
        )
    );
});

// ------------------ VERIFY EMAIL ------------------
const verifyEmail = asyncHandler (async (req, res) => {
    const { verificationToken } = req.params;

    if (!verificationToken) {
        throw new ApiError(400, "Email verification token is missing");
    }

    const hashedToken = crypto
        .createHash("sha256")
        .update(verificationToken)
        .digest("hex");

    const user = await User.findOne({
        emailVerificationToken: hashedToken,
        emailVerificationExpiry: { $gt: Date.now() }
    });

    if (!user) {
        throw new ApiError(400, "Token is invalid or expired");
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpiry = undefined;
    await user.save({ validateBeforeSave: false });

    return res.status(200).json(
        new APIResponse(200, {}, "Email verified successfully")
    );
});

const resendEmailverification = asyncHandler (async (req, res) => {
    const user = await User.findById(req.user?._id);

    if(!user){
        throw new ApiError(404, "User does not exits")
    }
    if(user.isEmailVerified){
        throw new ApiError(409, "User does not exits")
    }

     const { unHashedToken, hashedToken, tokenExpiry } =
        user.generateTemporaryToken();

    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    await sendEmail({
        email: user?.email,
        subject: "Please verify your email",
        mailgenContent: emailVerificationMailgenContent(
            user.username,
            `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
        ),
    });

    return res
    .status(200)
    .json(
        new APIResponse(
            200,
            {},
            "Mail has been sent to your email Id "
        )
    );

    });

    // -------------- Refresh Access Token --------
const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized access");
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        );

        const user = await User.findById(decodedToken?._id);
        if (!user) {
            throw new ApiError(401, "Invalid refresh token");
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token has expired");
        }

        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        };

        const { accessToken, refreshToken: newRefreshToken } =
            await generateAccessTokenAndRefreshToken(user._id);

        user.refreshToken = newRefreshToken;
        await user.save({ validateBeforeSave: false });

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new APIResponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed"
                )
            );
    } catch (error) {
        throw new ApiError(401, "Invalid or expired refresh token");
    }
});

// ------------------ EXPORTS ------------------
export { 
  registerUser, 
  login, 
  logoutUser, 
  getCurrentUser, 
  verifyEmail, 
  resendEmailverification, 
  refreshAccessToken 
};

