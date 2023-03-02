import pool from "../config/db.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { ErrorResponse } from "../utils/errorResponse.js";

class User {
  constructor(
    email,
    name,
    password,
    phone,
    id = "",
    resetPasswordExpire = "",
    resetPasswordToken = ""
  ) {
    this.email = email;
    this.name = name;
    this.password = password;
    this.phone = phone;
    this.id = id;
    this.resetPasswordExpire = resetPasswordExpire;
    this.resetPasswordToken = resetPasswordToken;
  }
  async save() {
    let sql = `INSERT INTO users (email,name,password,phone) 
    VALUES (
      '${this.email}',
      '${this.name}',
      '${this.password}',
      '${this.phone}')`;
    const [newUser, _] = await pool.execute(sql);
    return newUser;
  }
  static async getAllUsers(element = "*") {
    let sql = `select ${element} from users`;
    const [users, _] = await pool.execute(sql);
    return users;
  }
  static async getUserByID(id) {
    try {
      let sql = `select * from users where id='${id}'`;
      const [user, _] = await pool.execute(sql);
      if (!user)
        return new ErrorResponse(`there is no user with this email`, 404);

      return user;
    } catch (error) {
      console.log(error);
    }
  }
  static async getUserByEmail(email) {
    let sql = `select * from users where email='${email}'`;
    const [user, _] = await pool.execute(sql);
    return user;
  }
  static async UpdateById(id, { email, name, phone }) {
    let sql = `update users 
    set email = '${email}', name='${name}', phone='${phone}'
    where id = '${id}'`;
  }
  // sign JWT and return
  getSignedJwtToken() {
    return jwt.sign({ id: this.id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRE,
    });
  }
  // match user entered password to hashed password in database
  async matchPassword(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
  }
  // generate and hash password token
  getResetPasswordToken() {
    // generate token
    const resetToken = crypto.randomBytes(20).toString("hex");

    // hash token and set to resetPasswordToken field
    this.resetPasswordToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // set expire
    this.resetPasswordExpire = Date.now() + 10 * 1000 * 60;

    return resetToken;
  }

  async updateToken() {
    try {
      let sql = `UPDATE users SET reset_token = '${this.resetPasswordToken}',
       reset_token_expires_at = '${this.resetPasswordExpire}' WHERE email = '${this.email}'`;
      await pool.execute(sql);
    } catch (error) {
      return new ErrorResponse("Internal server error", 500)
    }
  }
}

export default User;
