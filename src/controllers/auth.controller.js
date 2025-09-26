import { User } from "../models/user.models.js";
import { APIResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";
import { StatusCodes } from "http-status-codes";

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
        "-password -refreshToken -emailVerificationExpiry"
    );

    if (!createdUser) {
        throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            "Something went wrong while registering a user"
        );
    }

    return res
        .status(StatusCodes.CREATED)
        .json(
            new APIResponse(
                StatusCodes.CREATED,
                { user: createdUser },
                "User registered successfully and verification email has been sent on your email."
            )
        );
});

const login = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        throw new ApiError(400, "User does not exist");
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(400, "Invalid credentials");
    }

    const { accessToken, refreshToken } = await generateAccessTokenAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken -emailVerificationExpiry"
    );

    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict", // optional, helps prevent CSRF
    };

    return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new APIResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken,
                    refreshToken
                },
                "User logged in successfully"
            )
        );
});
export { registerUser, login };
