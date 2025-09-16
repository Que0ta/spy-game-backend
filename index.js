import { createClient } from "@supabase/supabase-js";
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
//
import bcrypt, { compareSync } from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { rateLimit } from "express-rate-limit";

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1min
  limit: 40, // Limit each IP to 40 requests per `window`
  standardHeaders: "draft-8", // draft-6: `RateLimit-*` headers; draft-7 & draft-8: combined `RateLimit` header
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
  ipv6Subnet: 64, // Set to 60 or 64 to be less aggressive, or 52 or 48 to be more aggressive
});

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

async function getLobbyAdmin(adminUser) {
  const { data, error } = await supabase
    .from("lobbies")
    .select("players") // replace with your column name
    .eq("admin", adminUser);

  return data[0].players;
}

async function insertNewWord(id, word) {
  const { error } = await supabase
    .from("users")
    .update({ words: word })
    .eq("id", id);
}

async function getWords() {
  const { data, error } = await supabase.from("words").select("word");
  return data;
}

async function registerUser(user, pass) {
  const { error } = await supabase
    .from("users")
    .insert({ username: user, password: pass, balance: 0 });
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

// --- Weighted random helpers ---
function weightedRandomChoice(playerIds, weights) {
  const totalWeight = playerIds.reduce(
    (sum, id) => sum + (weights[id] || 1),
    0
  );
  let random = Math.random() * totalWeight;

  for (const id of playerIds) {
    random -= weights[id] || 1;
    if (random <= 0) return id;
  }
}

function chooseSpies(playerIds, spyCount, weights) {
  const chosen = new Set();

  while (chosen.size < spyCount && chosen.size < playerIds.length) {
    const spyId = weightedRandomChoice(playerIds, weights);
    chosen.add(spyId);
  }

  return Array.from(chosen);
}

app.get("/", (req, res) => {
  res.redirect("/users");
});

app.get("/users", verifyToken, async (req, res) => {
  try {
    const username = req.user.username; // from verifyToken middleware
    const user = await getSpecificUser(username);

    if (!user) {
      return res.status(404).json({ status: "not found" });
    }
    // Send only necessary info (avoid sending password)
    res.json({
      username: user.username,
      balance: user.balance, // assuming user.balance exists
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "error" });
  }
});

// MARK: add-word
app.post("/add-word", verifyToken, limiter, async (req, res) => {
  const username = req.user.username;
  const wantedWord = req.body;
  const user = await getSpecificUser(username);
  const allWords = user.words || [];
  const double = allWords.includes(wantedWord.word.toLowerCase());
  if (double === false) {
    allWords.push(wantedWord.word);
    const insertio = await insertNewWord(user.id, allWords);
  } else {
    res.status(200).json({
      status: "false",
      data: allWords,
    });
  }
  res.status(200).json({
    status: "success",
    data: allWords,
  });
});

app.get("/custom", verifyToken, async (req, res) => {
  const username = req.user.username;
  const user = await getSpecificUser(username);
  const allWords = user.words || [];
  res.json(allWords);
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
      { expiresIn: 1000 * 60 * 15 }
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

app.post("/delete-word", verifyToken, async (req, res) => {
  const username = req.user.username;
  const deleteWord = req.body.word;
  const user = await getSpecificUser(username);
  const words = user.words;
  if (words.includes(deleteWord)) {
    // console.log('exists!');
    const { data, error } = await supabase
      .from("users")
      .select("words")
      .eq("id", user.id)
      .single();

    if (!error) {
      const newWords = data.words.filter((w) => w !== deleteWord);

      await supabase
        .from("users")
        .update({ words: newWords })
        .eq("id", user.id);
    }
    console.log(data, error);
  } else {
    console.log("not completed!");
  }
  res.json("Success!");
});

app.get("/words", verifyToken, async (req, res) => {
  // console.log('fetch words');
  const data = await getWords();
  const wordList = [];
  data.forEach((keyWord) => {
    wordList.push(keyWord.word);
  });
  return res.json(wordList);
});

// GET lobby data by ID (needs a double check)
app.get("/lobby", verifyToken, async (req, res) => {
  const admin = req.user.username;

  const { data, error } = await supabase
    .from("lobbies")
    .select("*")
    .eq("admin", admin)
    .single();

  if (error) {
    return res.status(500).json({ error: error.message, status: false });
  }
  // data should include: players (JSON), word, id
  res.json({
    lobbyId: data.id,
    word: data.word,
    players: data.players, // array of {id, name, role}
    status: true,
  });
});

// passing data to DB when new game is started
app.post("/game-start", verifyToken, async (req, res) => {
  const adminy = req.user.username;
  const { players, spyAmount, wordsList } = req.body;

  // Pick random word
  const validWords = Object.keys(wordsList).filter((word) => wordsList[word]);
  const word = validWords[Math.floor(Math.random() * validWords.length)];

  // Pick spies
  const playerIds = Object.keys(players);
  const spyCount = Math.min(spyAmount.amount, playerIds.length);
  const weights = Object.fromEntries(playerIds.map((id) => [id, 1]));
  const spyIds = chooseSpies(playerIds, spyCount, weights);

  // Build players array with roles
  const playersWithRoles = playerIds.map((id) => ({
    id,
    name: players[id],
    role: spyIds.includes(id) ? "spy" : "civilian",
    status: "",
  }));

  // Needs a double lobby check (for 1 user)
  const { check, err } = await supabase
    .from("lobbies")
    .select("*")
    .eq("admin", adminy)
    .single();

  if (err) {
    return res.status(500).json({ error: err.message });
  } else if (check != undefined) {
    // Save into Supabase
    const { data, error } = await supabase
      .from("lobbies")
      .insert([{ word: word, players: playersWithRoles, admin: adminy }]);

    if (error) {
      console.error(error);
      return res.status(500).json({ error: "Failed to save game" });
    }
    res.json({ word, players: playersWithRoles });
  } else {
    // delete all previous
    const { data, error } = await supabase
      .from("lobbies")
      .delete()
      .eq("admin", adminy); // deletes ALL rows

    // add a new lobby
    const { data2, error2 } = await supabase
      .from("lobbies")
      .insert([{ word: word, players: playersWithRoles, admin: adminy }]);

    if (error2) {
      console.error(error2);
      return res.status(500).json({ error: "Failed to save game" });
    }
    res.json({ word, players: playersWithRoles });
  }
});

app.post("/update-role", verifyToken, async (req, res) => {
  const admin = req.user.username;
  const [name, status] = req.body;

  const dataOld = await getLobbyAdmin(admin);

  dataOld.forEach((item) => {
    if (item.name === name) {
      item.status = status;
    }
  });

  const { data, error } = await supabase
    .from("lobbies")
    .update({ players: dataOld })
    .eq("admin", admin);

  res.json(true);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
