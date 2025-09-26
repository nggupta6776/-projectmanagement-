import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-error.js";

// Export as 'validator'
export const validator = (req, res, next) => {
    const errors = validationResult(req);
    if (errors.isEmpty()) {
        return next();
    }

    const extractedErrors = errors.array().map(err => ({ [err.path]: err.msg }));

    throw new ApiError(
        422,
        "Received data is not valid",
        extractedErrors
    );
};
