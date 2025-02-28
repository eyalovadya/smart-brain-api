const express = require("express");
const bodyParser = require("body-parser"); // latest version of exressJS now comes with Body-Parser!
const bcrypt = require("bcrypt-nodejs");
const cors = require("cors");
const knex = require("knex");
const morgan = require("morgan");

const register = require("./controllers/register");
const signin = require("./controllers/signin");
const signout = require("./controllers/signout");
const profile = require("./controllers/profile");
const image = require("./controllers/image");
const { requireAuth } = require("./controllers/authorization");

const db = knex({
  // connect to your own database here:
  client: "pg",
  connection: {
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false,
    },
  },
});

const app = express();

app.use(morgan("combined"));
app.use(cors());
app.use(express.json()); // latest version of exressJS now comes with Body-Parser!

app.get("/", (req, res) => {
  // res.send(db.users);
  res.send("This is working");
});
app.post("/signin", signin.signinAuthentication(db, bcrypt));
app.post("/register", (req, res) => {
  register.handleRegister(req, res, db, bcrypt);
});
app.get("/signout", requireAuth, (req, res) => {
  signout.handleSignout(req, res);
});

app.get("/profile/:id", requireAuth, (req, res) => {
  profile.handleProfileGet(req, res, db);
});
app.post("/profile/:id", requireAuth, (req, res) => {
  profile.handleProfileUpdate(req, res, db);
});
app.put("/image", requireAuth, (req, res) => {
  image.handleImage(req, res, db);
});
app.post("/imageurl", requireAuth, (req, res) => {
  image.handleApiCall(req, res);
});

app.listen(process.env.PORT, () => {
  console.log(`app is running on port ${process.env.PORT}`);
});
