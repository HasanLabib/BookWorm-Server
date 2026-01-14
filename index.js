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

const bookStorage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    if (file.mimetype === "application/pdf") {
      const cleanName = file.originalname.replace(".pdf", "");

      return {
        folder: "book_pdf",
        resource_type: "raw",
        format: "pdf",
        type: "upload",
        public_id: Date.now() + "-" + cleanName,
      };
    }

    return {
      folder: "book_photo",
      type: "upload",
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
      public_id: Date.now() + "-" + file.originalname,
    };
  },
});

const uploadBook = multer({ storage: bookStorage });

const uploadProfile = multer({ storage: photoStorage });

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    //await client.connect();
    // Send a ping to confirm a successful connection
    //await client.db("admin").command({ ping: 1 });
    const BookWormDb = client.db("BookWormDb");
    const userCollection = BookWormDb.collection("users");
    const genreCollection = BookWormDb.collection("genres");
    const bookCollection = BookWormDb.collection("books");

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

    const issueTokens = async (user, res) => {
      user.accessSecret = generateSecret();
      user.refreshSecret = generateSecret();
      const query = { _id: user?._id };
      await userCollection.updateOne(query, {
        $set: {
          accessSecret: user?.accessSecret,
          refreshSecret: user?.refreshSecret,
        },
      });

      const new_accessToken = createAccessToken(user);
      const new_refreshToken = createRefreshToken(user);

      res.cookie("accessToken", new_accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: isProduction ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      res.cookie("refreshToken", new_refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: isProduction ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
    };

    app.post("/refreshToken", verifyRefreshToken, async (req, res) => {
      const user = req.user;
      try {
        await issueTokens(user, res);
        res.json({ message: "Session refreshed" });
      } catch (err) {
        res.status(401).json({ message: "Invalid refresh token" });
      }
    });

    app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      if (!email || !password)
        return res.status(400).json({ message: "Email and password required" });

      const user = await userCollection.findOne({ email });
      if (!user)
        return res.status(401).json({ message: "Invalid credentials" });

      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid)
        return res.status(401).json({ message: "Invalid credentials" });

      await issueTokens(user, res);

      res.json({
        message: "Login successful",
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          photo: user.photo,
          role: user.role,
        },
      });
    });
    app.post("/logout", verifyAccessToken, async (req, res) => {
      const user = req.user;

      await userCollection.updateOne(
        { _id: user._id },
        {
          $set: {
            accessSecret: generateSecret(),
            refreshSecret: generateSecret(),
          },
        }
      );

      res.clearCookie("accessToken", {
        httpOnly: true,
        secure: true,
        sameSite: isProduction ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: true,
        sameSite: isProduction ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({ message: "Logged out successfully" });
    });

    app.post("/add-genre", verifyAccessToken, async (req, res) => {
      const user = req.user;
      if (user.role != "admin")
        return res.status(403).json("User is not an admin");
      console.log(req.body);
      const { genre, icon } = req.body;

      query = { genre: genre };

      const existingGenre = await genreCollection.findOne(query);
      if (existingGenre)
        return res.status(409).json({ message: "Genre already exists" });

      const genreData = { genre, icon, createdAt: new Date() };

      const result = await genreCollection.insertOne(genreData);
      res.status(201).json({
        message: "Genre added successfully",
        insertedId: result.insertedId,
        genre: genreData,
      });
    });

    app.get("/genre", async (req, res) => {
      const genres = await genreCollection.find().toArray();
      res.json({ genres });
    });

    app.put("/update-genre/:id", verifyAccessToken, async (req, res) => {
      const user = req.user;
      if (user.role != "admin")
        return res.status(403).json("User is not an admin");
      console.log(req.body);
      const id = req.params.id;
      const { genre, icon } = req.body;

      query = { _id: new ObjectId(id) };

      const genreData = { genre, icon, createdAt: new Date() };

      const result = await genreCollection.updateOne(query, {
        $set: genreData,
      });
      res.status(201).json({
        message: "Genre edited successfully",
        upsertedId: result.upsertedId,
        modifiedCount: result.modifiedCount,
        genre: genreData,
      });
    });

    app.delete("/deleteGenre/:id", verifyAccessToken, async (req, res) => {
      const user = req.user;
      if (user.role != "admin")
        return res.status(403).json("User is not an admin");
      const id = req.params.id;
      query = { _id: new ObjectId(id) };

      const result = await genreCollection.deleteOne(query);
      res.status(201).json({
        message: "Genre edited successfully",
        acknowledged: true,
        deletedCount: result.deletedCount,
      });
    });

    app.post(
      "/add-book",
      verifyAccessToken,
      uploadBook.fields([
        { name: "cover", maxCount: 1 },
        { name: "pdf", maxCount: 1 },
      ]),
      async (req, res) => {
        const user = req.user;
        if (user.role !== "admin")
          return res.status(403).json("User is not an admin");

        const { title, author, genre, description } = req.body;

        const cover = req.files.cover[0].path;
        const pdf = req.files.pdf[0].path;

        const bookData = {
          title,
          author,
          genre,
          description,
          cover,
          pdf,
          rating: 0,
          ratingCount: 0,
          shelvedCount: 0,
          createdAt: new Date(),
        };

        const result = await bookCollection.insertOne(bookData);

        res.status(201).json({
          message: "Book added successfully",
          insertedId: result.insertedId,
          book: bookData,
        });
      }
    );

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
