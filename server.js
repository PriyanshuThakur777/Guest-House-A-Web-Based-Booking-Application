import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import Booking from "./models/Booking.js";
import User from "./models/User.js";
import {
  createAdminToken,
  createUserToken,
  getAdminProfile,
  hashPassword,
  validateAdminCredentials,
  verifyAdminToken,
  verifyPassword,
  verifyToken,
} from "./utils/auth.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
let mongoConnectionPromise;

const connectToDatabase = async () => {
  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI is missing. Add it to your environment variables.");
  }

  if (mongoose.connection.readyState === 1) {
    return;
  }

  if (!mongoConnectionPromise) {
    mongoConnectionPromise = mongoose.connect(MONGODB_URI);
  }

  await mongoConnectionPromise;
};

const createApprovalMessage = ({ name, room, checkin, checkout, guests }) => {
  return `Booking approved for ${name}. Your ${room} is confirmed from ${checkin} to ${checkout} for ${guests} guest(s).`;
};

const createStatusMessage = ({ name, room, checkin, checkout, guests, status }) => {
  if (status === "pending") {
    return `Booking for ${name} is pending review for ${room} from ${checkin} to ${checkout} for ${guests} guest(s).`;
  }

  if (status === "rejected") {
    return `Booking for ${name} could not be approved for ${room} from ${checkin} to ${checkout}.`;
  }

  return createApprovalMessage({ name, room, checkin, checkout, guests });
};

const requireAdminAuth = (req, res, next) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  const payload = verifyAdminToken(token);

  if (!payload) {
    return res.status(401).json({ message: "Unauthorized access." });
  }

  req.admin = payload;
  next();
};

const requireUserAuth = (req, res, next) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  const payload = verifyToken(token);

  if (!payload || payload.role !== "user") {
    return res.status(401).json({ message: "Please login first." });
  }

  req.user = payload;
  next();
};

app.use(cors());
app.use(express.json());
app.use(async (req, res, next) => {
  try {
    await connectToDatabase();
    next();
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
    res.status(500).json({ message: "Database connection failed." });
  }
});

app.get("/", (req, res) => {
  res.send("Guest House backend is running.");
});

app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body;

  if (!validateAdminCredentials(email, password)) {
    return res.status(401).json({ message: "Invalid admin email or password." });
  }

  res.json({
    message: "Login successful.",
    token: createAdminToken(),
    admin: getAdminProfile(),
  });
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email, and password are required." });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters." });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });

    if (existingUser) {
      return res.status(409).json({ message: "User already exists with this email." });
    }

    const user = await User.create({
      name,
      email: email.toLowerCase(),
      passwordHash: hashPassword(password),
    });

    const profile = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: "user",
    };

    res.status(201).json({
      message: "Account created successfully.",
      token: createUserToken(profile),
      user: profile,
    });
  } catch (error) {
    console.error("User signup failed:", error);
    res.status(500).json({ message: "Unable to create account right now." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user || !verifyPassword(password, user.passwordHash)) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const profile = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: "user",
    };

    res.json({
      message: "Login successful.",
      token: createUserToken(profile),
      user: profile,
    });
  } catch (error) {
    console.error("User login failed:", error);
    res.status(500).json({ message: "Unable to login right now." });
  }
});

app.get("/api/auth/me", requireUserAuth, async (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      role: "user",
    },
  });
});

app.get("/api/admin/me", requireAdminAuth, (req, res) => {
  res.json({ admin: getAdminProfile() });
});

app.post("/api/bookings", async (req, res) => {
  try {
    const { name, email, checkin, checkout, room, guests, phone, message } = req.body;

    if (!name || !email || !checkin || !checkout || !room || !guests || !phone) {
      return res.status(400).json({ message: "Please fill in all required booking fields." });
    }

    const approvalMessage = createStatusMessage({
      name,
      room,
      checkin,
      checkout,
      guests,
      status: "pending",
    });

    const booking = await Booking.create({
      name,
      email,
      checkin,
      checkout,
      room,
      guests: Number(guests),
      phone,
      message,
      status: "pending",
      approvalMessage,
    });

    res.status(201).json({
      message: "Booking saved successfully.",
      approvalMessage,
      booking,
    });
  } catch (error) {
    console.error("Booking save failed:", error);
    res.status(500).json({ message: "Unable to save booking right now." });
  }
});

app.get("/api/admin/bookings", requireAdminAuth, async (req, res) => {
  try {
    const bookings = await Booking.find().sort({ createdAt: -1 });
    res.json({ bookings });
  } catch (error) {
    console.error("Unable to load bookings:", error);
    res.status(500).json({ message: "Unable to load bookings right now." });
  }
});

app.patch("/api/admin/bookings/:id", requireAdminAuth, async (req, res) => {
  try {
    const { status } = req.body;

    if (!["approved", "pending", "rejected"].includes(status)) {
      return res.status(400).json({ message: "Invalid booking status." });
    }

    const booking = await Booking.findById(req.params.id);

    if (!booking) {
      return res.status(404).json({ message: "Booking not found." });
    }

    booking.status = status;
    booking.approvalMessage = createStatusMessage({
      name: booking.name,
      room: booking.room,
      checkin: booking.checkin,
      checkout: booking.checkout,
      guests: booking.guests,
      status,
    });
    booking.reviewedAt = new Date();

    await booking.save();

    res.json({
      message: "Booking updated successfully.",
      booking,
    });
  } catch (error) {
    console.error("Unable to update booking:", error);
    res.status(500).json({ message: "Unable to update booking right now." });
  }
});

app.delete("/api/admin/bookings/:id", requireAdminAuth, async (req, res) => {
  try {
    const booking = await Booking.findByIdAndDelete(req.params.id);

    if (!booking) {
      return res.status(404).json({ message: "Booking not found." });
    }

    res.json({ message: "Booking deleted successfully." });
  } catch (error) {
    console.error("Unable to delete booking:", error);
    res.status(500).json({ message: "Unable to delete booking right now." });
  }
});

const startServer = async () => {
  try {
    await connectToDatabase();
    console.log("MongoDB connected");

    app.listen(PORT, () => {
      console.log(`http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Server startup failed:", error.message);
  }
};

if (!process.env.VERCEL) {
  startServer();
}

export default app;
