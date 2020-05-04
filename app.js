// init setup
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');

const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(session({
  secret: process.env.PASSPORT_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// db connection

mongoose.connect("mongodb://localhost:27017/userDB", {
  useUnifiedTopology: true,
  useNewUrlParser: true
});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secrets: [String]
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// passport - Google OAuth2.0 connection

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // mongoose-findorcreate: https://www.npmjs.com/package/mongoose-findorcreate
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// endpoints

app.get("/", function(req, res){
  res.render("home");
});

app.route("/register")
.get(function(req, res){
  res.render("register");
})
.post(function(req, res){
  User.register({username:req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.route("/login")
.get(function(req, res){
  res.render("login");
})
.post(function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/auth/google", passport.authenticate("google", {scope: ["profile"]})
);

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }), function(req, res) {
  res.redirect("/secrets");
});

app.get("/secrets", function(req, res){
  User.find({"secrets": {$ne: null}}, function(err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.route("/submit")
.get(function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})
.post(function(req, res) {
  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      foundUser.secrets.push(req.body.secret);
      foundUser.save(function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

/*
// bcrypt implementations
// commenting out in favor of the passportjs implementation above

app.get("/register", function(req, res){
  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    if(err) {
      console.log(err);
      res.redirect("/register");
    } else {
      const user = new User({
        email: req.body.username,
        password: hash
      });
      user.save();
      // res.redirect("/secrets");
      res.render("secrets-bcrypt");
    }
  });
}

app.get("/login", function(req, res){
  User.findOne({email: req.body.username}, function(err, foundUser) {
    if (err) {
      console.log(err);
      res.redirect("/login");
    } else {
      if (foundUser) {
        bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
            if (result === true) {
              res.render("secrets-bcrypt");
            } else {
              res.redirect("/login");
            }
        });
      }
    }
  });
}
*/

// listener

app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
