import { createClient } from '@supabase/supabase-js';
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
// import bodyParser from 'body-parser';

dotenv.config()

const app = express();
app.use(cors({ origin: "http://localhost:5173" }));
app.use(express.json());

const port = 2000;

const supabase = createClient(
  process.env.DATABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

async function getUsers(){
    const { data, error } = await supabase
        .from('users')
        .select();
    return data;
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


app.get('/', (req,res)=>{
    res.redirect('/users');
})

app.get('/users', async (req, res)=>{
    const data = await getUsers();
    res.json(data);
})

app.post('/login', async (req,res)=>{
    const { login, password } = req.body;
    try{
        const user  = await getSpecificUser(login);
        if (user && user.password === password){
            res.json({ status: "logged", login: user.username });  
        } else if (user && user.password != password){
            res.json({ status: "pass", });
        } else{
            res.json({ status: "not", });
        }
    } 
    catch (error){
        console.log(error);
        res.status(500).json({ status: error });
    }
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});