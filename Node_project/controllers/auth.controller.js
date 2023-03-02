import asyncHandler from "../middleware/async.js";
import { ErrorResponse } from "../utils/errorResponse.js";
import User from "../models/user.js";
import sendEmail from "../utils/send_email.js";
import bcrypt from "bcryptjs";

// @desc     Register user
// @route    POST api/v1/auth/register
// @access   public
export const registerUser = asyncHandler(async (req, res, next) => {
  const { name, email, password, phone } = req.body;

  let user;
  // add encryption
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  // create user
  user = new User(email, name, hashedPassword, phone);

  await user.save();

  sendTokenResponse(user, 200, res);
});
// @desc     Login user
// @route    POST api/v1/auth/login
// @access   public
export const loginUser = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;

  // validate email and password
  if (!email || !password) {
    return next(new ErrorResponse("please provide an email and password", 400));
  }

  // check for user
  const test = await User.getUserByEmail(email);

  if (!test)
    return next(new ErrorResponse("email or password is not correct", 400));

  const user = new User(
    test[0].email,
    test[0].name,
    test[0].password,
    test[0].phone,
    test[0].id
  );
  // check if password matches
  const isMatch = await user.matchPassword(password);

  if (!isMatch) {
    return next(new ErrorResponse("invalid credentials", 401));
  }

  sendTokenResponse(user, 200, res);
});

//   get token from model, create cookie and send response
const sendTokenResponse = (user, statusCode, res) => {
  // create token
  const token = user.getSignedJwtToken();

  const options = {
    expires: new Date(
      process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000 + Date.now()
    ),
    httpOnly: true,
  };

  if (process.eventNames.NODE_ENV === "production") {
    options.secure = true;
  }

  res
    .status(statusCode)
    .cookie("token", token, options)
    .json({ success: true, token });
};
// @desc     Get current logged in user
// @route    GET api/v1/auth/me
// @access   Privet
export const getMe = asyncHandler(async (req, res, next) => {

  res.status(200).json({ success: true, data: req.user });
});
// @desc     Forgot password
// @route    POST api/v1/auth/forgotpassword
// @access   Privet
export const forgotPassword = asyncHandler(async (req, res, next) => {
  const test = await User.getUserByEmail(req.body.email);
  console.log(test);
  const user = new User(test[0].email,  test[0].name, test[0].password, test[0].phone, test[0].id);
  console.log(user);
  if (!user) {
    return next(new ErrorResponse(`there is no user with that email`, 404));
  }

  // get reset token
  const resetToken = user.getResetPasswordToken();

  await user.updateToken();

  // create reset URL
  const resetURL = `${req.protocol}://${req.get(
    "host"
  )}/api/v1/auth/forgotpassword/${resetToken}`;

  const message = `the reset pass is \n\n ${resetURL}`;

  try {
    console.log("object",user.email);
    await sendEmail({
      email: user.email,
      subject: "password reset token",
      message,
    });

    res.status(200).json({ success: true, data: "email sent" });
  } catch (error) {
    console.log(error);
    user.resetPasswordExpire = undefined;
    user.resetPasswordToken = undefined;

    await user.updateToken();

    return next(new ErrorResponse("email could not be sent", 500));
  }

  res.status(200).json({ success: true, data: user });
});
// @desc     Reset password
// @route    PUT api/v1/auth/resetpassword/:
// @access   Public
export const resetPassword = asyncHandler(async (req, res, next) => {
  // get hashed token
  const resetPasswordToken = crypto
    .createHash("sha256")
    .update(req.params.resetpassword)
    .digest("hex");

  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) {
    return next(new ErrorResponse("invalid token", 400));
  }

  // set new password
  user.password = req.body.password;
  user.resetPasswordExpire = undefined;
  user.resetPasswordToken = undefined;
  await user.save();

  sendTokenResponse(user, 200, res);
});
// @desc     Update user details
// @route    PUT api/v1/auth/updatedetails
// @access   Privet
export const updateDetails = asyncHandler(async (req, res, next) => {
  const fieldsToUpdate = {
    name: req.body.name,
    email: req.body.email,
    phone: req.body.phone,
  };

  const user = await User.UpdateById(req.user.id, fieldsToUpdate);

  res.status(200).json({ success: true, data: user });
});
// @desc     Update password
// @route    PUT api/v1/auth/updatepassword
// @access   Privet
export const updatePassword = asyncHandler(async (req, res, next) => {
  const user = await User.getUserByID(req.user.id);

  // check current password
  if (!(await user.matchPassword(req.body.currentPassword))) {
    return next(new ErrorResponse("password is not correct", 401));
  }

  user.password = req.body.newPassword;
  await user.save();

  sendTokenResponse(user, 200, res);
});
// @desc     Log user out & clear cookie
// @route    Get api/v1/auth/logout
// @access   Privet
export const logout = asyncHandler(async (req, res, next) => {
  res.cookie("token", "none", {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  req.user = undefined;

  res.status(200).json({ success: true, data: {} });
});
