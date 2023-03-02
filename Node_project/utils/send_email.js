import nodemailer from "nodemailer";

// async..await is not allowed in global scope, must use a wrapper
const sendEmail = async (options) => {
  // create reusable transporter object using the default SMTP transport
  const transporter = nodemailer.createTransport({
    service: "hotmail",
    auth: {
      user: process.env.HOTMAIL_EMAIL,
      pass: process.env.HOTMAIL_PASSWORD,
    },
  });

  const message = {
    from: process.env.HOTMAIL_EMAIL, // sender address
    to: options.email, // list of receivers
    subject: options.subject, // Subject line
    text: options.message, // plain text body
  };

  const info = await transporter.sendMail(message);
  console.log("Message sent: %s", info.response);
};

export default sendEmail;
