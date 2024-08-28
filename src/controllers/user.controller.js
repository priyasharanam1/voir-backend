import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import mongoose from "mongoose";
import {
  uploadOnCloudinary,
  deleteFromCloudinary,
} from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

// Utility function to extract public_id from a Cloudinary URL
const extractPublicIdFromUrl = (url) => {
  return url.split("/").pop().split(".")[0];
};

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
    $unset: { refreshToken: 1 },
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
  const incomingRefreshToken =
    req.cookies?.refreshToken || req.body.refreshToken;

  // Check if the refresh token is present
  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized request"); // Return an error if no refresh token is provided
  }

  try {
    // Verify the refresh token using the secret key
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

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
    const { accessToken, newRefreshToken } =
      await generateAccessAndRefreshTokens(user._id);

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

const changeCurrentPassword = asyncHandler(async (req, res) => {
  // Destructure the oldPassword and newPassword from the request body
  const { oldPassword, newPassword } = req.body;

  // Retrieve the currently authenticated user using the user ID from the request
  const user = await User.findById(req.user?._id);

  // Check if the old password provided is correct
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

  // If the old password is incorrect, throw an error
  if (!isPasswordCorrect) {
    throw new ApiError(400, "Incorrect old password");
  }

  // Update the user's password to the new password
  user.password = newPassword;

  // Save the updated user without running validation before saving (useful if other fields are not being updated)
  await user.save({ validateBeforeSave: false });

  // Return a success response
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully!"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  // Return a 200 status response with the currently authenticated user's details
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current user fetched successfully"));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
  // Destructure fullName and email from the request body
  const { fullName, email } = req.body;

  // Validate that all required fields are provided
  if (!fullName || !email) {
    throw new ApiError(400, "All the fields are required");
  }

  // Update the user's account details using their ID from req.user
  const user = await User.findByIdAndUpdate(
    req.user?._id, // Ensure req.user._id is provided
    {
      $set: { fullName, email },
    },
    {
      new: true, // Return the updated document
    }
  ).select("-password"); // Exclude password from the returned user object

  // Send the updated user object in the response
  return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"));
});

// const updateUserAvatar = asyncHandler(async (req, res) => {
//   const avatarLocalPath = req.file?.path;
//   if (!avatarLocalPath) {
//     throw new ApiError(400, "Avatar file is missing");
//   }
//   const avatar = await uploadOnCloudinary(avatarLocalPath);
//   if (!avatar) {
//     throw new ApiError(400, "Error while uploading avatar file on cloudinary");
//   }
//   const user = await User.findByIdAndUpdate(
//     req.user?._id,
//     {
//       $set: { avatar: avatar.url },
//     },
//     { new: true }
//   ).select("-password");

//   if (user.avatar) {
//     // Assuming `user.avatar` stores the Cloudinary public_id
//     const publicId = user.avatar.split('/').pop().split('.')[0]; // Extract the public_id from the URL
//     await deleteFromCloudinary(publicId);
//   }

//   return res
//     .status(200)
//     .json(new ApiResponse(200, user, "Avatar image updated successfully"));
// });

// const updateUserCoverImage = asyncHandler(async (req, res) => {
//   const coverImageLocalPath = req.file?.path;
//   if (!coverImageLocalPath) {
//     throw new ApiError(400, "Cover image file is missing");
//   }
//   const coverImage = await uploadOnCloudinary(coverImageLocalPath);
//   if (!coverImage) {
//     throw new ApiError(
//       400,
//       "Error while uploading cover image file on cloudinary"
//     );
//   }
//   const user = await User.findByIdAndUpdate(
//     req.user?._id,
//     {
//       $set: { coverImage: coverImage.url },
//     },
//     { new: true }
//   ).select("-password");

//   if (user.coverImage) {
//     // Assuming `user.avatar` stores the Cloudinary public_id
//     const publicId = user.coverImage.split('/').pop().split('.')[0]; // Extract the public_id from the URL
//     await deleteFromCloudinary(publicId);
//   }

//   return res
//     .status(200)
//     .json(new ApiResponse(200, user, "Cover image updated successfully"));
// });

// Update user avatar
const updateUserAvatar = asyncHandler(async (req, res) => {
  const avatarLocalPath = req.file?.path;
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is missing");
  }

  // Find the user first to get the current avatar
  const user = await User.findById(req.user?._id).select("-password");
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  // Upload the new avatar
  const newAvatar = await uploadOnCloudinary(avatarLocalPath);
  if (!newAvatar) {
    throw new ApiError(400, "Error while uploading avatar file on Cloudinary");
  }

  // Delete the old avatar from Cloudinary if it exists
  if (user.avatar) {
    const oldAvatarPublicId = extractPublicIdFromUrl(user.avatar);
    await deleteFromCloudinary(oldAvatarPublicId);
  }

  // Update the user with the new avatar
  user.avatar = newAvatar.url;
  await user.save();

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Avatar image updated successfully"));
});

// Update user cover image
const updateUserCoverImage = asyncHandler(async (req, res) => {
  const coverImageLocalPath = req.file?.path;
  if (!coverImageLocalPath) {
    throw new ApiError(400, "Cover image file is missing");
  }

  // Find the user first to get the current cover image
  const user = await User.findById(req.user?._id).select("-password");
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  // Upload the new cover image
  const newCoverImage = await uploadOnCloudinary(coverImageLocalPath);
  if (!newCoverImage) {
    throw new ApiError(
      400,
      "Error while uploading cover image file on Cloudinary"
    );
  }

  // Delete the old cover image from Cloudinary if it exists
  if (user.coverImage) {
    const oldCoverImagePublicId = extractPublicIdFromUrl(user.coverImage);
    await deleteFromCloudinary(oldCoverImagePublicId);
  }

  // Update the user with the new cover image
  user.coverImage = newCoverImage.url;
  await user.save();

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Cover image updated successfully"));
});

const getUserChannelProfile = asyncHandler(async (req, res) => {
  const { username } = req.params;

  // Validate that the username is provided and is not just whitespace
  if (!username?.trim()) {
    throw new ApiError(400, "Username is missing!");
  }

  const channel = await User.aggregate([
    {
      // Match the user based on the provided username (case-insensitive)
      $match: {
        username: username.toLowerCase(),
      },
    },
    {
      // Perform a lookup to get all subscriptions where the user is the channel
      // This will give us the list of subscribers for this user
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers",
      },
    },
    {
      // Perform another lookup to get all subscriptions where the user is the subscriber
      // This will give us the list of channels that the user is subscribed to
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo",
      },
    },
    {
      // Add computed fields to the aggregation result
      $addFields: {
        // Calculate the number of subscribers
        subscribersCount: {
          $size: "$subscribers",
        },
        // Calculate the number of channels the user is subscribed to
        channelsSubscribedToCount: {
          $size: "$subscribedTo",
        },
        // Determine if the logged-in user is subscribed to this channel
        isSubscribed: {
          $in: [req.user?._id, "$subscribers.subscriber"], // Check if req.user._id is among the subscribers
        },
      },
    },
    {
      // Project only the required fields in the final output
      $project: {
        fullName: 1,
        username: 1,
        subscribersCount: 1,
        channelsSubscribedToCount: 1,
        isSubscribed: 1,
        avatar: 1,
        coverImage: 1,
        email: 1,
      },
    },
  ]);

  // If no channel was found, throw a 404 error
  if (!channel.length) {
    throw new ApiError(404, "Channel does not exist");
  }

  // Return the first item from the array since we're expecting only one result
  return res
    .status(200)
    .json(
      new ApiResponse(200, channel[0], "User channel fetched successfully")
    );
});

const getWatchHistory = asyncHandler(async (req, res) => {
  // Aggregate query to fetch watch history for the logged-in user
  const user = await User.aggregate([
    {
      // Match the user by their _id using req.user._id
      $match: {
        _id: new mongoose.Types.ObjectId(req.user._id),
      },
    },
    {
      // Lookup the "videos" collection based on the video IDs stored in the "watchHistory" array
      $lookup: {
        from: "videos", // Collection to join
        localField: "watchHistory", // Field in the User collection (array of video IDs)
        foreignField: "_id", // Field in the Video collection (video ID)
        as: "watchHistory", // Output array field containing the matched videos
        pipeline: [
          {
            // Lookup the "users" collection to fetch details of the video owner
            $lookup: {
              from: "users", // Collection to join (User details)
              localField: "owner", // Field in the Video collection (owner's ID)
              foreignField: "_id", // Field in the User collection (user's ID)
              as: "owner", // Output array field containing the matched user (owner) details
              pipeline: [
                {
                  // Project only the required fields (fullName, username, avatar) from the owner
                  $project: {
                    fullName: 1,
                    username: 1,
                    avatar: 1,
                  },
                },
              ],
            },
          },
          {
            // Flatten the "owner" array to a single object using $first
            $addFields: {
              owner: {
                $first: "$owner",
              },
            },
          },
        ],
      },
    },
  ]);

  // If the aggregation is successful, respond with the watch history
  return res
    .status(200)
    .json(new ApiResponse(200, user[0]?.watchHistory || [], "Watch history fetched successfully"));
});


export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory
};
