// init setup
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

// db connection

mongoose.connect("mongodb://localhost:27017/userDB", {
  useUnifiedTopology: true,
  useNewUrlParser: true
});
mongoose.set("useCreateIndex", true);

const userSchema = {
  email: String,
  password: String,
  googleId: String,
  secrets: [String]
};

const User = new mongoose.model("User", userSchema);

// endpoints

app.get("/", function(req, res){
  res.render("home");
});

app.route("/register")
.get(function(req, res){
  res.render("register");
})
.post(function(req, res){
  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    if(err) {
      console.log(err);
      res.redirect("register");
    } else {
      const user = new User({
        email: req.body.username,
        password: hash
      });
      user.save();
      // res.redirect("secrets");
      res.render("secrets-bcrypt");
    }
  });
});

app.route("/login")
.get(function(req, res){
  res.render("login");
})
.post(function(req, res){
  User.findOne({email: req.body.username}, function(err, foundUser) {
    if (err) {
      console.log(err);
      res.redirect("login");
    } else {
      if (foundUser) {
        bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
            if (result === true) {
              res.render("secrets-bcrypt");
            } else {
              res.redirect("login");
            }
        });
      }
    }
  });
});

// app.get("/secrets", function(req, res){
//   res.render("secrets");
// });

// listener

app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
