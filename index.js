import { createClient } from "@supabase/supabase-js";
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
//
import bcrypt, { compareSync } from "bcrypt";
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

async function getWords() {
  const { data, error } = await supabase.from("words").select("word");
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
    .select("*") // only select what you need
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

app.get("/users", verifyToken ,async (req, res) => {
  try {
    const username = req.user.username; // from verifyToken middleware
    const user = await getSpecificUser(username);

    if (!user) {
      return res.status(404).json({ status: "not found" });
    }

    // Send only necessary info (avoid sending password)
    res.json({
      username: user.username,
      balance: user.balance,  // assuming user.balance exists
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "error" });
  }
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
      maxAge: 1000 * 60 * 60 * 24 * 365, // 1 hour, adjust as needed
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

app.get("/words", verifyToken, async (req, res)=> {
  // console.log('fetch words');
  const data = await getWords();
  const wordList = [];
  data.forEach((keyWord) => {
    wordList.push(keyWord.word);
  })
  return res.json(wordList);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
