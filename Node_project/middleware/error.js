import { ErrorResponse } from "../utils/errorResponse.js";

export const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;
  // log to console for dev
  console.log(err);
  // mongoose bad object id
  if (err.name === "CastError") {
    const message = `Resource not found`;
    error = new ErrorResponse(message, 404);
  }
  // mongoose duplicate key
  if (err.code === 11000) {
    const message = "duplicate field value entered";
    error = new ErrorResponse(message, 400);
  };
//   mongoose validation error 
if(err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(error => error.message);
    error = new ErrorResponse(message, 400)
}

  res.status(error.statusCode || 500).json({
    success: false,
    error: error.message || "server error",
  });
};
