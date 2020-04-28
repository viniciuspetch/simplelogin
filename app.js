const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { Client } = require("pg");
const path = require("path");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const port = 8000;

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

getClient = function () {
  return new Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
  });
};

profile = function (req, res) {
  var username = jwt.verify(res.locals.token, process.env.SECRET).username;
  var client = getClient();
  client
    .connect()
    .then(() =>
      client.query("SELECT * from users WHERE username=$1", [username])
    )
    .then((dbres) => {
      if (!dbres.rows[0]) {
        res.sendStatus(401);
        return null;
      }
      res.json({ username, id: dbres.rows[0].id });
    })
    .catch((err) => {
      console.log(err);
      res.sendStatus(512);
    })
    .finally(() => client.end());
};

verify = function (req, res) {
  var username = jwt.verify(res.locals.token, process.env.SECRET).username;
  var client = getClient();
  client
    .connect()
    .then(() =>
      client.query("SELECT * from users WHERE username=$1", [username])
    )
    .then((dbres) => {
      if (!dbres.rows[0]) {
        res.sendStatus(401);
        return null;
      }
      res.sendStatus(200);
    })
    .catch((err) => {
      console.log(err);
      res.sendStatus(512);
    })
    .finally(() => client.end());
};

signUp = function (req, res) {
  var username = req.body.username;
  var password = bcrypt.hashSync(req.body.password, 5);
  var client = getClient();
  client
    .connect()
    .then(() =>
      client.query("SELECT * FROM users WHERE username = $1", [username])
    )
    .then((dbres) => {
      if (dbres.rows[0] != undefined) {
        res.sendStatus(401);
        return null;
      }
      return client.query(
        "INSERT INTO users(username, password) VALUES ($1, $2) RETURNING *",
        [username, password]
      );
    })
    .then((dbres) => {
      if (dbres) {
        res.status(200);
        res.redirect("/");
      }
    })
    .catch((err) => {
      console.log(err);
      res.sendStatus(512);
    })
    .finally(() => client.end());
};

login = function (req, res) {
  var username = req.body.username;
  var password = req.body.password;
  var client = getClient();
  client
    .connect()
    .then(() =>
      client.query("SELECT * FROM users WHERE username = $1", [username])
    )
    .then((dbres) => {
      if (!dbres.rows[0]) {
        res.sendStatus(401);
      } else {
        if (!bcrypt.compareSync(password, dbres.rows[0].password)) {
          res.sendStatus(401);
        } else {
          var token = jwt.sign({ username }, process.env.SECRET, {
            expiresIn: "1d",
          });
          res.cookie("token", token);
          res.json({
            token,
          });
        }
      }
    })
    .catch((err) => {
      console.log(err);
      res.sendStatus(512);
    })
    .finally(() => client.end());
};

app.get("/", (req, res) => res.sendFile(path.join(__dirname + "/index.html")));
app.get("/login", (req, res) =>
  res.sendFile(path.join(__dirname + "/login.html"))
);
app.post("/login", login);
app.get("/signup", (req, res) =>
  res.sendFile(path.join(__dirname + "/signup.html"))
);
app.post("/signup", signUp);
app.get("/verify", (req, res) =>
  res.sendFile(path.join(__dirname + "/verify.html"))
);
app.post(
  "/verifyBody",
  (req, res, next) => {
    res.locals.token = req.body.token;
    next();
  },
  verify
);
app.post(
  "/verifyCookie",
  (req, res, next) => {
    res.locals.token = req.cookies.token;
    next();
  },
  verify
);

app.get("/profile", (req, res) =>
  res.sendFile(path.join(__dirname + "/profile.html"))
);
app.post(
  "/profileBody",
  (req, res, next) => {
    res.locals.token = req.body.token;
    next();
  },
  profile
);
app.post(
  "/profileCookie",
  (req, res, next) => {
    res.locals.token = req.cookies.token;
    next();
  },
  profile
);

app.listen(process.env.PORT || port, () => console.log("Server is ready"));
