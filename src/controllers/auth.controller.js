import { User } from "../models/user.models.js";
import { APIResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import {emailVerificationMailgenContent, sendEmail} from "../utils/mail.js";

const generateAccessTokenAndRefreshToken = async (userId) => {
    try {
       const user = await User.findById(userId)
      const accessToken = user.generateAccessToken();
       const refreshToken = user.generateRefrashToken();
       
       user.refreshToken = refreshToken
       await user.save({validateBeforeSave: false})
       return {accessToken, refreshToken}
    } catch (error) {
        throw new ApiError(
            500,
            "Somethings went wrong while generating access"
        )
        
    }
}

const registerUser = asyncHandler(async (req, res) => {
    const { email, username, password, role } = req.body;

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    });

    if(existedUser){
        throw new ApiError(409, "user with email or username already exists",[])
    }
    const user = await User.create({
        email,
        password,
        username,
        isEmailVerifed: false
    })

   const { unHashedToken, hashedToken, tokenExpiry } = 
   user.genrateTemporaryToken();

    // ...rest of your registration logic...

    user.emailVerificationToken = hashedToken
    user.emailVerificationExpiry = tokenExpiry

    await user.save({validateBeforeSave: false})

    await sendEmail(
        {
            email: user?.email,
            subject: "please verify your email",
            mailgenContent: emailVerificationMailgenContent(
                user.username,
                `${req.protocol}://${req.res("host")}/api/v1/users/verify-email/${unHashedToken}`
            ),
        }
    )
     const createdUser = await User.findById(user._id).select(
        "-password -refreshToken -emailVerificationExpiry",
    );

    if(!createdUser){
        throw new ApiError(500, "Something went Wrong while registring A user")
    }

    return res
    .status(201)
    .json(
        new APIResponse(
            200,
            {user:createdUser},
            "User registerd succesfully and verification email has been sent on your email."
        )
    )
});

export { registerUser };
   


