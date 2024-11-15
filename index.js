// Values
const express = require("express");
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();
const bcrypt = require('bcryptjs');

const db = new sqlite3.Database('./users.db');

let message = " ";

app.use(session({
  secret: 'your-secret-key',  // Change this to a stronger secret in production
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set `secure: true` if using HTTPS in production
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));

// You Can Add async By removing the /* And */
// You Can Change The / Its For {Link}/ Example {Link}/replit
app.get('/', (req, res) => {
  res.render('home');
});

app.get('/register', (req, res) => {
  res.render('register');
});

// Handle form submission from the registration page
app.post('/register', (req, res) => {
  const { username, email, password, bio, profile_picture } = req.body;

  // Check if all required fields are provided
  if (!username || !email || !password) {
      return res.status(400).send('Username, email, and password are required.');
  }

  // Hash the password before storing it in the database
  bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
          console.error('Error hashing password:', err);
          return res.status(500).send('Error hashing password');
      }

      // Attempt to save the user to the database
      db.run("INSERT INTO users (username, email, password, bio, profile_picture) VALUES (?, ?, ?, ?, ?)",
          [username, email, hashedPassword, bio, profile_picture], 
          function(err) {
              if (err) {
                  console.error('Error saving user:', err.message); // Log detailed error
                  return res.status(500).send('Error saving user');
              }

              console.log('User registered successfully with ID:', this.lastID);
              res.redirect('/login');  // Redirect to the login page after successful registration
          });
  });
});


app.get('/login', (req, res) => {
  res.render('login');
});

// Handle form submission from the login page
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Check if username and password are provided
  if (!username || !password) {
      return res.status(400).send('Username and password are required.');
  }

  // Query the database for the user with the entered username
  db.get("SELECT id, username, email, password FROM users WHERE username = ?", [username], (err, user) => {
      if (err) return res.status(500).send('Database error');
      if (!user) return res.status(401).send('User not found');

      // Compare the entered password with the stored hashed password
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) return res.status(500).send('Error comparing passwords');
          if (!isMatch) return res.status(401).send('Invalid credentials');

          // Set up the session and log the user in
          req.session.userId = user.id;
          req.session.username = user.username;
          res.redirect(`/profile/${user.username}`); // Redirect to the user's profile page
      });
  });
});

function isAuthenticated(req, res, next) {
  if (!req.session.userId) {
      return res.redirect('/login');
  }
  next();
}

app.get('/profile/:username', isAuthenticated, (req, res) => {
  const username = req.params.username;

  // Get user info from the database
  db.get("SELECT id, username, email, bio, profile_picture FROM users WHERE username = ?", [username], (err, user) => {
      if (err) {
          console.error('Database error:', err);
          return res.status(500).send('Database error');
      }
      if (!user) {
          return res.status(404).send('User not found');
      }

      // Check if the logged-in user matches the requested profile
      const isOwner = user.username === req.session.username;

      // Render profile page, passing user data and isOwner flag
      res.render('profile', { user, isOwner });
  });
});

// Edit profile page (GET)
// Edit profile page (GET)
app.get('/profile/edit/:username', isAuthenticated, (req, res) => {
  const userId = req.session.userId;

  // Get the user's current profile data
  db.get("SELECT id, username, email, bio, profile_picture FROM users WHERE id = ?", [userId], (err, user) => {
      if (err) {
          console.error('Database error:', err);
          return res.status(500).send('Database error');
      }
      if (!user) {
          return res.status(404).send('User not found');
      }

      // Render the edit profile page with the user's data
      res.render('edit-profile', { user });
  });
});


app.post('/profile/edit', isAuthenticated, (req, res) => {
  const { email, bio, profile_picture } = req.body;
  const userId = req.session.userId;

  // Update the user's profile in the database
  db.run("UPDATE users SET email = ?, bio = ?, profile_picture = ? WHERE id = ?",
      [email, bio, profile_picture, userId], function(err) {
          if (err) {
              console.error('Error updating profile:', err);
              return res.status(500).send('Error updating profile');
          }

          console.log('Profile updated successfully');
          res.redirect(`/profile/${req.session.username}`); // Redirect back to the profile page
      });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
      if (err) return res.status(500).send('Error logging out');
      res.redirect('/login');
  });
});

// Dont Remove
app.listen(3000, () => {
  console.log("Project is ready!");
});