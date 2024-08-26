import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";

// Middleware to verify JWT and authenticate the user
export const verifyJWT = asyncHandler(async (req, _ , next) => {
  try {
    // Extract the token from either cookies or the Authorization header
    //authorization header is checked for token in case if the user is using our mobile app
    const token =
      req.cookies?.accessToken || // Check if token is stored in cookies
      req.header("Authorization")?.replace("Bearer ", ""); // Extract token from Authorization header

    // If no token is found, return an unauthorized error
    if (!token) {
      throw new ApiError(401, "Unauthorized request");
    }

    // Verify the token using the secret key
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    // Find the user by ID in the decoded token and exclude sensitive fields
    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );

    // If no user is found, return an error indicating the token is invalid
    if (!user) {
      throw new ApiError(401, "Invalid access token");
    }

    // Attach the authenticated user to the request object for use in the next middleware/controller
    req.user = user;

    // Move on to the next middleware or controller
    next();
  } catch (error) {
    // If token verification fails, handle it as an unauthorized error
    throw new ApiError(401, error?.message || "Invalid access token");
  }
});
