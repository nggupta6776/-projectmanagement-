import { APIResponse } from "../utils/api-response.js";
import { asyncHandler } from "../utils/async-handler.js";
/** 
const healthCheck =  async (req, res, next) => {
    try {
        const user = await getUserFromDB()
       res.status(200).json(
        new APIResponse(200, {message:"server is running"})
       );
    } catch (error) {
       next(err) 
    }
};
*/
const healthCheck = asyncHandler(async (req, res) => {
    res.status(200).json(new APIResponse(200, {message: "Server is still running"}));
});
export{ healthCheck }; 

