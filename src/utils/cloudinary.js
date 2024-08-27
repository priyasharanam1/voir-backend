import { v2 as cloudinary } from "cloudinary";
import fs from "fs";

// Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadOnCloudinary = async (localFilePath) => {
  try {
    if (!localFilePath) return null;
    const response = await cloudinary.uploader.upload(localFilePath, {
      resource_type: "auto",
    });
    // console.log("file is uploaded on cloudinary ", response.url);
    fs.unlinkSync(localFilePath);
    return response;
  } catch (error) {
    fs.unlinkSync(localFilePath); //remove the file saved locally because the file upload operation failed
    return null;
  }
};

// Function to delete a file from Cloudinary using its public_id
const deleteFromCloudinary = async (publicId) => {
  try {
    if (!publicId) return null;

    const response = await cloudinary.uploader.destroy(publicId);

    if (response.result !== "ok") {
      throw new Error("Failed to delete the image from Cloudinary.");
    }

    return response;
  } catch (error) {
    console.error("Error during Cloudinary deletion:", error);
    return null;
  }
};

export { uploadOnCloudinary, deleteFromCloudinary };
