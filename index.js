require("dotenv").config();
const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const https = require("https");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const app = express();

const SECRET_KEY = process.env.SECRET_KEY;
const USERS_FILE = path.join(__dirname, "users.json");

const options = {
  key: fs.readFileSync(process.env.SSL_KEY_PATH),
  cert: fs.readFileSync(process.env.SSL_CERT_PATH),
};

const transporter = nodemailer.createTransport({
  host: "smtp.zoho.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

const readUsers = () => {
  try {
    const data = fs.readFileSync(USERS_FILE, "utf8");
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
};

const writeUsers = (users) => {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again after 15 minutes.",
});

const checkForToken = (req, res, next) => {
  const token = req.cookies?.token;

  if (!token) {
    if (["/login", "/register", "/verify", "/verify_email"].includes(req.path)) {
      return next();
    }
    return res.redirect("/login");
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);

    const users = readUsers();
    const user = users.find(
      (u) => u.username === decoded.username && u.token === token
    );

    if (!user) {
      res.clearCookie("token");
      return res.redirect("/login");
    }

    req.user = user;
    next();
  } catch (err) {
    res.clearCookie("token");
    return res.redirect("/login");
  }
};

app.use(checkForToken);
app.use(limiter);

app.get("/verify", (req, res) => {
  const { code } = req.query;
  console.log("Verification attempt:", { code });
  const users = readUsers();
  const user = users.find((u) => u.verificationCode === code);
  if (!user) {
    console.log("User not found or code mismatch");
    return res.status(400).send("Invalid verification code.");
  }
  user.verified = true;
  writeUsers(users);
  res.redirect("/");
});

app.get("/:page?", (req, res) => {
  const page = req.params.page || "home";
  const filePath = path.join(__dirname, "views", `${page}.ejs`);

  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) {
      return res.status(404).render("404");
    }

    res.render("template", {
      title: page,
      page: page,
      user: req.user,
    });
  });
});


app.post("/register", async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password) {
    return res
      .status(400)
      .render("register", { error: "Email, username, and password are required" });
  }

  const users = readUsers();
  if (users.some((user) => user.username === username)) {
    return res
      .status(400)
      .render("register", { error: "Username already exists" });
  }

  if (users.some((user) => user.email === email)) {
    return res
      .status(400)
      .render("register", { error: "Email already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const verificationCode = (
    Math.random().toString(36).substring(2) +
    Math.random().toString(36).substring(2) +
    Math.random().toString(36).substring(2)
  )
    .substring(0, 28)
    .toUpperCase();
  
  const newUser = {
    id: users.length + 1,
    username,
    email,
    password: hashedPassword,
    verificationCode,
    verified: false,
    created_at: new Date().toISOString(),
  };

  users.push(newUser);
  writeUsers(users);

  const verificationLink = `${req.protocol}://${req.get("host")}/verify?code=${verificationCode}`;
  const mailOptions = {
    from: process.env.SMTP_USER,
    to: email,
    subject: "Email Verification",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; background-color: #f9f9f9; color: #333;">
          <h2 style="text-align: center; color: #4CAF50;">Welcome, ${username}!</h2>
          <p style="font-size: 16px; line-height: 1.5;">Thank you for joining us! To complete your registration, please verify your email address by clicking the link below:</p>
          <p style="text-align: center; margin: 20px 0;">
              <a href="${verificationLink}" style="font-size: 16px; color: #ffffff; background-color: #4CAF50; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify Your Email</a>
          </p>
          <p style="font-size: 14px; line-height: 1.5; color: #666;">Or, paste this link into your browser:</p>
          <p style="font-size: 14px; line-height: 1.5; color: #4CAF50; word-wrap: break-word;">${verificationLink}</p>
          <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
          <p style="font-size: 12px; line-height: 1.5; color: #999; text-align: center;">If you did not create an account, please ignore this email.</p>
      </div>
    `,
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      return res
        .status(500)
        .render("register", { error: "Error sending verification email" });
    }
    res.redirect("/verify_email");
  });
});

app.post("/verify", (req, res) => {
  const { email, verificationCode } = req.body;
  const users = readUsers();
  const user = users.find(
    (user) => user.email === email && user.verificationCode === verificationCode
  );

  if (!user)
    return res
      .status(400)
      .json({ message: "Invalid email or verification code" });

  user.verified = true;
  writeUsers(users);
  res.status(200).json({ message: "Email verified successfully" });
});

app.post("/login", async (req, res) => {
  const { identifier, password } = req.body;
  
  if (!identifier || !password) {
    return res
      .status(400)
      .render("login", { error: "Identifier and password are required" });
  }

  const users = readUsers();
  const user = users.find(
    (user) =>
      (user.username === identifier || user.email === identifier)
  );

  if (!user) {
    return res
      .status(400)
      .render("login", { error: "Invalid username or email" });
  }

  if (!user.verified) {
    return res
      .status(400)
      .render("login", { error: "Email not verified. Please check your inbox." });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res
      .status(400)
      .render("login", { error: "Incorrect password" });
  }

  const token = jwt.sign({ username: user.username, ip: req.ip }, SECRET_KEY, {
    expiresIn: "48h",
  });

  user.token = token;
  writeUsers(users);

  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    maxAge: 48 * 60 * 60 * 1000,
  });
  res.redirect("home");
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  const users = readUsers();
  const user = users.find((u) => u.username === req.user.username);
  if (user) {
    delete user.token;
    writeUsers(users);
  }
  res.status(200).json({ message: "Logout successful" });
});

https.createServer(options, app).listen(443, () => {
  console.log("HTTPS Server running on port 443");
});
