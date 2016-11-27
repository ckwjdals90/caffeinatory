"use strict"

const PORT            = process.env.PORT || 8080;
const express         = require("express");
const app             = express();
const bodyParser      = require("body-parser");
const session         = require("express-session");
const bcrypt          = require("bcrypt");
const saltRounds      = 10;
const dbConfig        = require("./config/db");
const knex            = require('knex')({ client: 'pg', connection: dbConfig });
const dataHelpers     = require("./lib/util/data-helpers");   // saveMaps & getMaps

app.set("view engine", "ejs");
app.set('trust proxy', 1);

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true
}));

//     +---------------------------+
//     |     locals middleware     |
//     +---------------------------+

app.use((req, res, next) => {

  res.locals.current_user = null;
  if (req.session.current_user) {
    knex.select('*').from('users').where('username', req.session.current_user.username).asCallback(function(err, rows) {
      if (err) {
        console.log(err);
        next();
      }
      if (rows.length) {
        res.locals.current_user = rows[0];
      }
      next();
    })
  } else {
    next();
  }
})

//     +-----------------------------------+
//     |     whitelist page middleware     |
//     +-----------------------------------+

const WHITELISTED_PAGES = ["/", "/register", "/login"]
app.use(function(req, res, next) {
  console.log("My req.url: " + req.url);
  if(!WHITELISTED_PAGES.includes(req.url)) {
    const authorized = req.session.current_user
    if(!authorized) {
      res.redirect("/")
    }
  }
    next();
});



// ========================================== //

//         +-----------------------+
//         |   user registration   |
//         +-----------------------+

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  const input = req.body;

  if (input.email === "" || input.username === "" || input.password === "") {
    res.status(400).send("You are missing some inputs man")
  } else {

    knex.select('*').from('users').where('username', input.username).asCallback(function (err, rows) {
      if (err) throw err;
      if (rows.length !== 0) {
        res.status(400).send("Username unavaileble")
      } else {
        knex.select('*').from('users').where('email', input.email).asCallback(function (err, rows) {
          if (err) throw err;
          if (rows.length !== 0) {
            res.status(400).send("Email unavailable")
          } else {
            let enteredUsername   = input.username;
            let enteredEmail      = input.email;
            let enteredPassword   = input.password;
            bcrypt.hash(enteredPassword, saltRounds, (err, hash) => {
              const newUser = {
                username: enteredUsername,
                email:    enteredEmail,
                password: hash
              };
              console.log("newUser data:", newUser);
              knex.insert(newUser).into('users').asCallback(function (err, rows) {
                if (err) { console.log (err); throw err; }
              });
            })
            res.redirect("/");
          }
        });
      }
    });
  }
});

//         +------------------------+
//         |     login & logout     |
//         +------------------------+

app.get("/", (req, res) => {
  res.render("login");
});

app.post("/", (req, res) => {
  const input = req.body
  var usernameFound    = "";
  var passwordFound    = "";
  var current_user     = "";

  knex.select('*').from('users').where('username', input.username).asCallback(function (err, rows) {
    if (err) throw err;
    if (rows.length !== 0) {
      usernameFound = rows[0].username;
      passwordFound = rows[0].password;
      current_user  = rows[0]
      if (input.username === usernameFound) {
        console.log("email found in the db");
        bcrypt.compare(input.password, passwordFound, (err, passwordMatch) => {
          if (passwordMatch) {
            // console.log("current_user: ", current_user)
            req.session.current_user = current_user;
            res.redirect(`/users/${input.username}`);
            return;
          } else {
            console.log("wrong password");
            res.status(401).send("Invalid username or password");
            return;
          }
        })
      } else {
        console.log("username not found");
        res.status(401).send("Invalid username or password");
        return;
      }
    }
  });
});

app.post("/logout", (req, res) => {
  req.session.current_user = undefined;
  res.redirect("/")
});



