import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

// Function to generate access and refresh tokens for a user
const generateAccessAndRefreshTokens = async (userId) => {
  try {
    // Find user by ID
    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    // Generate tokens
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    // Store refresh token in the database
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating access and refresh tokens"
    );
  }
};

// Controller to handle user registration
const registerUser = asyncHandler(async (req, res) => {
  const { fullName, email, username, password } = req.body;

  // Validate if all required fields are provided
  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // Check if a user with the same username or email already exists
  const existingUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existingUser) {
    throw new ApiError(
      409,
      "User with the same email or username already exists"
    );
  }

  // Check for avatar image in the request
  const avatarLocalPath = req.files?.avatar?.[0]?.path;
  let coverImageLocalPath;

  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  // Avatar is mandatory for user registration
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar image is required");
  }

  // Upload images to Cloudinary
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = coverImageLocalPath
    ? await uploadOnCloudinary(coverImageLocalPath)
    : null;

  // Create a new user in the database
  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(), // Save username in lowercase
  });

  // Retrieve and select specific fields to send back to the frontend
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // Send a successful response
  return res
    .status(201)
    .json(new ApiResponse(201, createdUser, "User registered successfully"));
});

// Controller to handle user login
const loginUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body;

  // Ensure username or email is provided for login
  if (!username && !email) {
    throw new ApiError(400, "Enter either username or email");
  }

  // Find user by username or email
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (!user) {
    throw new ApiError(404, "User not found!");
  }

  // Validate the provided password
  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials");
  }

  // Generate access and refresh tokens
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  // Select specific user details to return to the frontend
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const cookieOptions = {
    httpOnly: true, // Ensure cookies are only accessible via HTTP (no JavaScript access)
    secure: true, // Set secure flag to true in production
    // sameSite: "Strict",
  };

  // Set cookies and return the user details along with tokens
  return res
    .status(200)
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", refreshToken, cookieOptions)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in successfully!"
      )
    );
});

// Controller to handle user logout
const logoutUser = asyncHandler(async (req, res) => {
  // Remove the refresh token from the user's record
  await User.findByIdAndUpdate(req.user._id, {
    $set: { refreshToken: undefined },
  });

  const cookieOptions = {
    httpOnly: true,
    secure: true,
    // sameSite: "Strict",
  };

  // Clear cookies and send a success response
  return res
    .status(200)
    .clearCookie("accessToken", cookieOptions)
    .clearCookie("refreshToken", cookieOptions)
    .json(new ApiResponse(200, {}, "User logged out successfully"));
});

// Controller function to handle refreshing access tokens
const refreshAccessToken = asyncHandler(async (req, res) => {
  // Retrieve the refresh token from cookies or request body
  const incomingRefreshToken = req.cookies?.refreshToken || req.body.refreshToken;

  // Check if the refresh token is present
  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized request"); // Return an error if no refresh token is provided
  }

  try {
    // Verify the refresh token using the secret key
    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

    // Find the user by the ID stored in the decoded refresh token
    const user = await User.findById(decodedToken?._id);
    if (!user) {
      throw new ApiError(401, "Unauthorized request"); // Return an error if the user does not exist
    }

    // Check if the provided refresh token matches the stored refresh token for the user
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used"); // Return an error if the tokens do not match
    }

    // Define cookie options to ensure cookies are HTTP-only and secure
    const cookieOptions = {
      httpOnly: true,
      secure: true, // Set to true if serving over HTTPS
      // sameSite: 'strict', 
    };

    // Generate new access and refresh tokens for the user
    const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user._id);

    // Set the new tokens in cookies and send them in the response
    return res
      .status(200)
      .cookie("accessToken", accessToken, cookieOptions)
      .cookie("refreshToken", newRefreshToken, cookieOptions)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed successfully"
        )
      );
  } catch (error) {
    // Handle any errors during token verification or generation
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

export { registerUser, loginUser, logoutUser, refreshAccessToken };
