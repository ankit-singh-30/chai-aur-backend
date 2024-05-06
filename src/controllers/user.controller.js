import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req, res) => {
  // get user details from frontend
  // validation - not empty
  // check if user already exist : username, email
  // check  for images, check for avtar
  // upload cloudinary, avtar
  // create user object - create entry in db
  // remove password and token field from response
  // check for user creation
  // return response

  const { username, fullname, email, password } = req.body;
  if (
    [fullname, username, email, password].some((filed) => filed?.trim() === "")
  ) {
    throw new ApiError(400, "All Fileds are required");
  }

  const existedUser = User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username is already exists");
  }

  //console.log(req.body);
  //console.log(req.files);

  const avtarLocalPath = req.files?.avtar[0]?.path;
  const coverLocalPath = req.files?.coverImage[0]?.path;

  if (!avtarLocalPath) {
    throw new ApiError(400, "Avtar File is required");
  }

  const avtar = await uploadOnCloudinary(avtarLocalPath);
  const coverImage = await uploadOnCloudinary(coverLocalPath);

  if (!avtar) {
    throw new ApiError(400, "Avtar File is required");
  }

  const user = await User.create({
    fullname,
    avtar: avtar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while register the user");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfully"));
});

export { registerUser };
