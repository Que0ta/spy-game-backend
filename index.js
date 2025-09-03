import { createClient } from "@supabase/supabase-js";
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
//
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

dotenv.config();

const JWT_SECRET = process.env.SUPER_KEY;

const app = express();
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.PROD_URL, // dev + prod
    credentials: true, // allow sending cookies
  })
);
app.use(express.json());

const port = 2000;

const supabase = createClient(
  process.env.DATABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

function verifyToken(req, res, next) {
  const token = req.cookies.token; // ✅ check cookies
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = decoded; // attach decoded JWT info
    next();
  });
}

app.get("/dashboard", verifyToken, (req, res) => {
  res.json({ user: req.user.username });
});

async function getUsers() {
  const { data, error } = await supabase.from("users").select();
  return data;
}

async function registerUser(user, pass) {
  const { error } = await supabase
    .from("users")
    .insert({  username: user, password: pass, balance: 0 });
}

async function getSpecificUser(login) {
  const { data, error } = await supabase
    .from("users")
    .select("username, password") // only select what you need
    .eq("username", login)
    .single(); // returns a single object instead of array

  if (error) {
    // console.log("Supabase error:", error);
    return null; // return null if not found or error
  }
  return data; // object { username, password }
}

app.get("/", (req, res) => {
  res.redirect("/users");
});

app.get("/users", async (req, res) => {
  const data = await getUsers();
  res.json(data);
});

app.post("/login", async (req, res) => {
  const { login, password } = req.body;

  try {
    const user = await getSpecificUser(login);
    if (!user) {
      return res.json({ status: "not" }); // user not found
    }

    // ✅ Compare entered password with hashed password in DB
    const validPass = await bcrypt.compare(password.trim(), user.password);
    if (!validPass) {
      return res.json({ status: "pass" }); // wrong password
    }

    // ✅ Create JWT with username
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: 1000*60*15 }
    );

    // ✅ Save JWT in HTTP-only cookie (cannot be read by JS)
    res.cookie("token", token, {
      httpOnly: true, // secure against XSS
      secure: true, // set true on HTTPS (hosting)
      sameSite: "strict",
      maxAge: 1000 * 60 * 15, // 1 hour, adjust as needed
    });

    res.json({ status: "logged", login: user.username });
  } catch (error) {
    console.log(error);
    res.status(500).json({ status: "error" });
  }
});

app.post("/register", async (req, res) => {
  const { login, password } = req.body;
  const updatedPass = await bcrypt.hash(password, 10);
  await registerUser(login, updatedPass);
  return res.redirect("/");
});

app.post("/logout", (req, res) => {
  res.cookie("token", "", {
    httpOnly: true,
    secure: true, // true if using HTTPS
    sameSite: "strict",
    expires: new Date(0), // expire immediately
  });
  res.json({ status: "not" });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
