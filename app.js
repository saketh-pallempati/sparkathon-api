import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { User } from "./models/User.js";
import { v4 as uuidv4 } from 'uuid';


dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(
    cors({
        origin: [
            "https://daksh-soc-terminal.vercel.app",
            "https://daksh-soc-2024.vercel.app",
            "https://daksh-leaderboard.vercel.app",
        ],
        credentials: true,
    })
);
app.use(cookieParser());

// Router
const router = express.Router();

router.post("/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            uuid: uuidv4()
        });

        // Save the new user
        const savedUser = await newUser.save();
        if (!savedUser) {
            return res.status(500).json({ status: false, message: "Record not registered" });
        }

        return res.status(201).json({ status: true, message: "Record registered" });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User is not registered" });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: "Password is incorrect" });
        }

        const token = jwt.sign({ id: user._id }, process.env.KEY, {
            expiresIn: "36h",
        });
        res.cookie("token", token, {
            httpOnly: true,
            sameSite: "none",
            secure: true,
        });

        return res.json({ status: true, message: "Login successful" });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

router.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({ message: "User not registered" });
        }

        const token = jwt.sign({ id: user._id }, process.env.KEY, {
            expiresIn: "5m",
        });

        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: "saketh.pallempati@gmail.com",
                pass: process.env.NODEMAIL,
            },
        });

        const encodedToken = encodeURIComponent(token).replace(/\./g, "%2E");
        const mailOptions = {
            from: "saketh.pallempati@gmail.com",
            to: email,
            subject: "Reset Password",
            text: `http://localhost:5173/resetPassword/${encodedToken}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.json({ message: "Error sending email" });
            } else {
                return res.json({ status: true, message: "Email sent" });
            }
        });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

router.post("/reset-password/:token", async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;
        const decoded = jwt.verify(token, process.env.KEY);
        const hashPassword = await bcrypt.hash(password, 10);
        await User.findByIdAndUpdate(decoded.id, { password: hashPassword });

        return res.json({ status: true, message: "Password updated" });
    } catch (error) {
        return res.json({ message: "Invalid token" });
    }
});

router.get("/logout", (req, res) => {
    res.clearCookie("token");
    return res.json({ status: true });
});

const verifyUser = async (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.json({ status: false, message: "No token" });
        }

        const decoded = jwt.verify(token, process.env.KEY);
        const user = await User.findById(decoded.id);
        if (!user) {
            return res.json({ status: false, message: "User not found" });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.json({ message: error.message });
    }
};

router.get("/get-uuid/:email", verifyUser, async (req, res) => {
    try {
        const { email } = req.params;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        return res.json({ uuid: user.uuid });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.use("/api", router);

mongoose.connect(process.env.MONGO, { dbName: "Wallmart_Sparkathon" })
    .then(() => console.log("MongoDB connected"))
    .catch((error) => console.log("MongoDB connection error:", error));

app.listen(process.env.PORT, () => {
    console.log(`Server is running at http://localhost:${process.env.PORT}`);
});