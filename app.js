const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { Client } = require("pg");
const path = require("path");

const port = 8000;
const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

getClient = function () {
  return new Client({
    user: "postgres",
    host: "localhost",
    database: "simplelogin",
    password: "postgres",
    port: "5432",
  });
};

verify = function (req, res) {
  var username = jsonwebtoken.verify(token, secret).username;
  var client = getClient();
  client
    .connect()
    .then(() =>
      client.query("SELECT * from users WHERE username=$1", [username])
    )
    .then((dbres) => {
      if (dbres.rows[0] != undefined) {
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
          var token = jwt.sign({ username, expiration: Date.now()+86400000 }, "nodejs");
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

app.listen(port, () => console.log("Working at " + port));
