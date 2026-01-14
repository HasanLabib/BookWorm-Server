require("dotenv").config();
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const app = express();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;

const port = process.env.PORT || 5000;
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://your-frontend-domain.vercel.app",
    ],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.set("trust proxy", 1);

app.get("/", async (req, res) => {
  res.send("Bookwarm server is run");
});

const uri = `mongodb+srv://${process.env.MONGOUSER}:${process.env.MONGOPASS}@programmingheroassignme.7jfqtzz.mongodb.net/?appName=ProgrammingHeroAssignment`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

const generateSecret = () => crypto.randomBytes(32).toString("hex");
const createAccessToken = (user) =>
  jwt.sign({ id: user._id }, user.accessSecret, { expiresIn: "50m" });

const createRefreshToken = (user) =>
  jwt.sign({ id: user._id }, user.refreshSecret, { expiresIn: "20d" });

const photoStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "profile_photo",
    allowed_formats: [
      "jpg",
      "jpeg",
      "png",
      "gif",
      "webp",
      "avif",
      "svg",
      "heic",
    ],
    transformation: [
      { fetch_format: "auto" },
      { quality: "auto" },
      { crop: "fill", gravity: "auto" },
    ],
  },
});

const uploadProfile = multer({ storage: photoStorage });

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    //await client.connect();
    // Send a ping to confirm a successful connection
    //await client.db("admin").command({ ping: 1 });
    const BookWormDb = client.db("BookWormDb");
    const userCollection = BookWormDb.collection("users");

    app.post("/register", uploadProfile.single("photo"), async (req, res) => {
      const user = req.body;
      if (!user?.name)
        return res.status(400).json({ message: "Name required" });
      if (!user?.email)
        return res.status(400).json({ message: "Email required" });
      if (!user?.password)
        return res.status(400).json({ message: "Password required" });
      if (!req.file) return res.status(400).json({ message: "Photo required" });

      const hashPasword = await bcrypt.hash(user?.password, 10);
      user.password = hashPasword;

      user.role = "user";
      user.createdAt = new Date();
      user.photo = req.file?.path;
      user.accessSecret = generateSecret();
      user.refreshSecret = generateSecret();

      const query = { email: user?.email };
      const existingUser = await userCollection.findOne(query);

      if (existingUser) {
        return res.status(409).json({ message: "User already exists" });
      } else {
        //console.log(user);
        const result = await userCollection.insertOne(user);
        user._id = result.insertedId;
        const accessToken = createAccessToken(user);
        const refreshToken = createRefreshToken(user);

        res.cookie("accessToken", accessToken, {
          httpOnly: true,
          secure: true,
          sameSite: isProduction ? "none" : "lax",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: isProduction ? "none" : "lax",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        console.log(result);
        res.status(201).json({
          message: "Registration successful",
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            photo: user.photo,
            role: user.role,
          },
        });
      }
    });

    const verifyAccessToken = async (req, res, next) => {
      const token = req.cookies.accessToken;

      if (!token) return res.status(401).json({ message: "Not Logged In" });

      try {
        const decodedToken = jwt.decode(token);
        if (!decodedToken.id)
          return res.status(401).json({ message: "Invalid token" });

        const query = { _id: new ObjectId(decodedToken?.id) };
        const user = await userCollection.findOne(query);
        if (!user) return res.status(401).json({ message: "User not found" });

        jwt.verify(token, user.accessSecret);
        req.user = user;
        next();
      } catch (err) {
        return res.status(401).json({ message: "Session expired" });
      }
    };

    const verifyRefreshToken = async (req, res, next) => {
      const token = req.cookies.refreshToken;

      if (!token) return res.status(401).json({ message: "No refresh token" });

      try {
        const decodedToken = jwt.decode(token);
        if (!decodedToken.id)
          return res.status(401).json({ message: "Invalid token" });

        const query = { _id: new ObjectId(decodedToken?.id) };
        const user = await userCollection.findOne(query);
        if (!user) return res.status(401).json({ message: "User not found" });

        jwt.verify(token, user.refreshSecret);
        req.user = user;
        next();
      } catch (err) {
        return res.status(401).json({ message: "Session expired" });
      }
    };

    app.get("/logged_in", verifyAccessToken, async (req, res) => {
      const user = req.user;
      return res.json({
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          photo: user.photo,
          role: user.role,
        },
      });
    });

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`Bookworm server is running on port: ${port}`);
});
