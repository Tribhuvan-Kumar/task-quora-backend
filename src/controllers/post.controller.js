import { Post } from "../models/post.model.js";

import mongoose from "mongoose";

import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const createNewPost = asyncHandler(async (req, res) => {
  try {
    const { title, description, isCompleted } = req.body;
    if (
      [title, description].some((field) => {
        field.trim() === "";
      })
    ) {
      throw new ApiError(400, "All fields are required!");
    }

    const currentUserId = req?.user?._id;
    if (!currentUserId) {
      throw new ApiError(401, "Unauthorized request for new post!");
    }

    const existedPost = await Post.findOne({
      title,
      ownerOfPost: currentUserId,
    });
    if (existedPost) {
      throw new ApiError(409, "Post already exists with same title!");
    }

    const post = await Post.create({
      title,
      description,
      isCompleted,
      ownerOfPost: currentUserId,
    });

    const savedPost = await Post.findById(post._id).select("-ownerOfPost");

    return res
      .status(201)
      .json(new ApiResponse(200, savedPost, "Post uploaded successfully!"));
  } catch (error) {
    throw new ApiError(500, "Failed to save Post, Please try again later!");
  }
});

const getUserPosts = asyncHandler(async (req, res) => {
  try {
    const currentUserId = req?.user?._id;
    if (!currentUserId) {
      throw new ApiError(401, "Unauthorized request for user posts!");
    }

    const userPosts = await Post.find({ ownerOfPost: currentUserId }).select(
      "-ownerOfPost"
    );

    return res
      .status(200)
      .json(
        new ApiResponse(200, userPosts, "User posts retrieved successfully!")
      );
  } catch (error) {
    throw new ApiError(500, "Failed to retrieve user posts!");
  }
});

const updatePost = asyncHandler(async (req, res) => {
  try {
    const { _id, title, description, isCompleted } = req.body;
    if (
      [title, description].some((field) => {
        return field.trim() === "";
      })
    ) {
      throw new ApiError(400, "All fields are required!");
    }

    const existedPost = await Post.findByIdAndUpdate(
      _id,
      {
        title,
        description,
        isCompleted,
      },
      { new: true }
    ).select("-ownerOfPost");
    if (!existedPost) {
      throw new ApiError(404, "Post not found with the provided credentials!");
    }

    return res
      .status(201)
      .json(new ApiResponse(200, existedPost, "Post updated successfully!"));
  } catch (error) {
    throw new ApiError(500, "Failed to update posts!");
  }
});

const deletePost = asyncHandler(async (req, res) => {
  const { _id } = req.body;

  if (!mongoose.isValidObjectId(_id)) {
    throw new ApiError(422, "Invalid credentials!");
  }

  const existedPost = await Post.findByIdAndDelete(_id);

  if (!existedPost) {
    throw new ApiError(404, "Post not found with the provided credentials!");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Post deleted successfully!"));
});

export { createNewPost, getUserPosts, updatePost, deletePost };
