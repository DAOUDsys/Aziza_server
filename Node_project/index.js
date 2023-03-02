import express from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import xss from "xss-clean";
import rateLimit from "express-rate-limit";
import hpp from "hpp";
import authRouter from "./router/auth.js"
import {errorHandler} from './middleware/error.js';

// load env vars
dotenv.config({ path: "./config/config.env" });

const app = express();

// body parser
app.use(express.json());

// app.use(cookieParser());

// set security headers
app.use(helmet());

// prevent XSS attacks
app.use(xss());

// enable cors
app.use(cors());

// rate limiting
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 mins
  max: 100,
});

app.use(limiter);

// prevent http param pollution
app.use(hpp());

// mount routers
app.use("/api/v1/auth", authRouter);

app.use(errorHandler);

const PORT = process.env.PORT || 5500;
const server = app.listen(
  PORT,
  console.log(`server running in ${process.env.NODE_ENV} mode on port ${PORT}`)
);

// handle unhandled promise rejections
process.on("unhandledRejection", (err, promise) => {
  console.log(`Error ${err.message}`);
  // close server & exit process
  server.close(() => process.exit(1));
});
