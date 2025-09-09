
import { Router } from "express";
import { db } from "../utils/db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const authRouter = Router();

// 🐨 Todo: Exercise #1

// Register endpoint
authRouter.post("/register", async (req, res) => {
		try {
			const { username, password, firstName, lastName } = req.body;
			if (!username || !password || !firstName || !lastName) {
				return res.status(400).json({ message: "All fields are required" });
			}
			const usersCollection = db.collection("users");
			const existingUser = await usersCollection.findOne({ username });
			if (existingUser) {
				return res.status(400).json({ message: "Username already exists" });
			}
			const hashedPassword = await bcrypt.hash(password, 10);
			await usersCollection.insertOne({
				username,
				password: hashedPassword,
				firstName,
				lastName,
			});
			return res.json({ message: "User has been created successfully" });
		} catch (err) {
			console.error("Register error:", err);
			return res.status(500).json({ message: "Internal server error" });
		}
});

// 🐨 Todo: Exercise #3

// Login endpoint
authRouter.post("/login", async (req, res) => {
	try {
		const { username, password } = req.body;
		if (!username || !password) {
			return res.status(400).json({ message: "Username and password are required" });
		}
		const usersCollection = db.collection("users");
		const user = await usersCollection.findOne({ username });
		if (!user) {
			return res.status(401).json({ message: "Invalid username or password" });
		}
		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch) {
			return res.status(401).json({ message: "Invalid username or password" });
		}
		const payload = {
			id: user._id,
			firstName: user.firstName,
			lastName: user.lastName,
		};
		const token = jwt.sign(payload, "secret-key", { expiresIn: "1d" });
		return res.json({ message: "login successfully", token });
	} catch (err) {
		return res.status(500).json({ message: "Internal server error" });
	}
});

export default authRouter;
