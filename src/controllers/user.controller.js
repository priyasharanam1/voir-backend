import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

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
  if ([fullName, email, username, password].some((field) => field?.trim() === "")) {
    throw new ApiError(400, "All fields are required");
  }

  // Check if a user with the same username or email already exists
  const existingUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existingUser) {
    throw new ApiError(409, "User with the same email or username already exists");
  }

  // Check for avatar image in the request
  const avatarLocalPath = req.files?.avatar?.[0]?.path;
  let coverImageLocalPath;

  if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  // Avatar is mandatory for user registration
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar image is required");
  }

  // Upload images to Cloudinary
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = coverImageLocalPath ? await uploadOnCloudinary(coverImageLocalPath) : null;

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
  const createdUser = await User.findById(user._id).select("-password -refreshToken");

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // Send a successful response
  return res.status(201).json(new ApiResponse(201, createdUser, "User registered successfully"));
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
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

  // Select specific user details to return to the frontend
  const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

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
  await User.findByIdAndUpdate(req.user._id, { $set: { refreshToken: undefined } });

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

export { registerUser, loginUser, logoutUser };
