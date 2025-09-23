import { User } from "../models/user.models.js";
import { APIResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";

const generateAccessTokenAndRefreshToken = async (userId) => {
    try {
       const user = await User.findById(userId)
      const accessToken = user.generateAccessToken();
       const refreshToken = user.generateRefrashToken();

    } catch (error) {
        
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
});

export { registerUser };