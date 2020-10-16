//jshint esversion:6
console.clear();
require('dotenv').config()
const express = require("express")
const bodyParser = require("body-parser")
const ejs = require("ejs")
const mongoose = require("mongoose")
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require("mongoose-findorcreate")

const app = express()

// ------ ENV Variables ------
const PORT = process.env.PORT || 3000
const ADMIN = process.env.ADMIN
const PASSWORD = process.env.PASSWORD
const DB = process.env.DB
const saltRounds = 10

app.use(express.static("public"))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({extended: true}))

app.use(session({
	secret: process.env.MYSECRET,
	resave: false,
	saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

const mongoURL = "mongodb+srv://" + ADMIN + ":" + PASSWORD + "@cluster0.s3mwb.mongodb.net/" + DB + "?retryWrites=true&w=majority"
mongoose.connect(mongoURL, {useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false})
mongoose.set("useCreateIndex", true)

// ------ Schemas ------

const userSchema = new mongoose.Schema ({
	username: { type: String, unique: true },
	email: String,
	password: String,
	provider: String,
	secrets: Array
})

userSchema.plugin(passportLocalMongoose, {
	usernameField: "username"
})
userSchema.plugin(findOrCreate)

// ------ Mongoose models ------
const User = mongoose.model("User", userSchema)

passport.use(User.createStrategy())

passport.serializeUser((user, done) => {
	done(null, user.id)
})

passport.deserializeUser((id, done) => {
	User.findById(id, (err, user) => {
		done(err, user)
	})
})

passport.use(new GoogleStrategy({
	clientID: process.env.CLIENT_ID,
	clientSecret: process.env.CLIENT_SECRET,
	callbackURL: "http://localhost:3000/auth/google/secrets",
	userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
	},
	(accessToken, refreshToken, profile, cb) => {
		User.findOrCreate({ username: profile.id }, { provider: "google", email: profile._json.email}, (err, user) => {
			return cb(err, user);
		})
	}
))

passport.use(new FacebookStrategy({
	clientID: process.env.FACEBOOK_APPID,
	clientSecret: process.env.FACEBOOK_SECRET,
	callbackURL: "http://localhost:3000/auth/facebook/secrets",
	profileFields: ["id", "email"]
},
(accessToken, refreshToken, profile, done) => {
	User.findOrCreate({ username: profile.id }, { provider: "facebook", email: profile._json.email }, function(err, user) {
		if (err) { return done(err); }
		done(null, user);
	});
}
));

app.get('/', (req, res) => {
	res.render("home")
})

app.get("/secrets", (req, res) => {
	if (req.isAuthenticated()) {
		User.find({secrets : {$exists : true, $not: {$size: 0}}}, (err, foundUsers) => {
			if (err) {
				console.log(err);
			} else {
				console.log(foundUsers);
				if (foundUsers)
					res.render("secrets", {Users: foundUsers})
			}
		})
	} else {
		res.redirect("/login")
	}
})

app.route("/submit")
	 .get((req, res) => {
			if (req.isAuthenticated()) {
				res.render("submit")
			} else {
				res.redirect("/login")
			}
	 })
	 .post((req, res) => {
		 const secret = req.body.secret

		 User.findById(req.user.id, (err, foundUser) => {
			 if (err) {
				 console.log(err);
			 } else {
				 if (foundUser) {
					 console.log(foundUser);
					 foundUser.secrets.push(secret)
					 foundUser.save((err) => {
						 if (err) {
							 console.log(err);
						 } else {
							 res.redirect("/secrets")
						 }
					 })
				 }
			 }
		 })
	 });

app.get("/auth/facebook", passport.authenticate("facebook", {scope: ["email"]}))

app.get("/auth/facebook/secrets", passport.authenticate("facebook", {failureRedirect: "/login"}), (req, res) => {
	res.redirect("/secrets")
})

app.get("/auth/google", passport.authenticate("google", {scope: ["profile", "email"]}))

app.get("/auth/google/secrets", passport.authenticate("google", {failureRedirect: "/login"}), (req, res) => {
	res.redirect("/secrets")
})

app.get("/logout", (req, res) => {
	req.logout()
	res.redirect("/")
})

app.route("/register")
	 .get((req, res) => {
		res.render("register")
	})
	 .post((req, res) => {
		 User.register({username: req.body.username}, req.body.password, (err, user) => {
			 if (err) {
				 console.log(err);
				 res.redirect("/register")
			 } else {
				 passport.authenticate("local")(req, res, () => {
					 User.updateOne({ _id: user._id}, {$set: {provider: "local", email: req.body.username}}, () => {
						 res.redirect("/secrets")
					 })
				 })
			 }
		 })
	});

app.route("/login")
	.get((req, res) => {
	 	res.render("login")
 })
	.post((req, res) => {
		const user = new User({
			username: req.body.username,
			password: req.body.password
		})
		req.login(user, (err) => {
			if (err) {
				console.log(err);
				res.redirect("/login")
			} else {
				passport.authenticate("local")(req, res, () => {
					res.redirect("/secrets")
				})
			}
		})
	});


app.listen(PORT, () => {
	console.log("Server successfully started on port: " + PORT);
})