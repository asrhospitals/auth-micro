const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");

function generateOtp() {
  return crypto.randomInt(1000, 9999).toString(); // Generate 4-digit OTP
}

async function hashOtp(otp) {
  return await bcrypt.hash(otp, 10);
}

const sendOtp = async (email, otp) => {
  // Set up the email transporter
  const transporter = nodemailer.createTransport({
    service: "gmail",
    secure: true,
    port: 465,

    auth: {
      user: process.env.EMAIL_USER, // your email
      pass: process.env.EMAIL_PASS, // your email password or app-specific password
    },
  });

  // Define email options
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your OTP Code",
    text: `Your OTP is: ${otp}`,
  };
  console.log(otp);

  // Send the email
  try {
    await transporter.sendMail(mailOptions);
    console.log("OTP sent successfully");
  } catch (error) {
    console.error("Error sending OTP:", error);
    throw new Error("Failed to send OTP");
  }
};

module.exports = { generateOtp, hashOtp, sendOtp };
