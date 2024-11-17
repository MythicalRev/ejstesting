// Values
const express = require("express");
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();
const bcrypt = require('bcryptjs');
const { isatty } = require("tty");

const db = new sqlite3.Database('./users.db');

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

// Middleware to check if user is an admin
function isAdmin(req, res, next) {
    if (req.session.isAdmin) {
        return next();  // User is admin, proceed to the next route
    }
    res.status(403).send('Forbidden: You do not have permission to access this resource');
}

// You Can Add async By removing the /* And */
// You Can Change The / Its For {Link}/ Example {Link}/replit
app.get('/', (req, res) => {
  const username = req.session.username;
  const isAdmin = req.session.isAdmin

  res.render('home', {username: username, isAdmin: isAdmin} );
});

app.get('/register', (req, res) => {
  res.render('register');
});

// Handle form submission from the registration page
app.post('/register', (req, res) => {
  const { username, email, password, bio, profile_picture, isAdmin } = req.body;

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
      db.run("INSERT INTO users (username, email, password, bio, profile_picture, isAdmin) VALUES (?, ?, ?, ?, ?, ?)",
          [username, email, hashedPassword, bio, profile_picture, isAdmin || false], 
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
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
      if (err) return res.status(500).send('Database error');
      if (!user) return res.status(401).send('User not found');

      // Compare the entered password with the stored hashed password
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) return res.status(500).send('Error comparing passwords');
          if (!isMatch) return res.status(401).send('Invalid credentials');

          // Set up the session and log the user in
          req.session.userId = user.id;
          req.session.username = user.username;
          req.session.isAdmin = user.isAdmin;  // Store isAdmin status in the session
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

app.get('/profile/:username', (req, res) => {
  const username = req.params.username;
  const isAdmin = req.session.isAdmin;

  // Get user info from the database
  db.get("SELECT id, username, email, bio, profile_picture, isAdmin FROM users WHERE username = ?", [username], (err, user) => {
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
      res.render('profile', { user, isOwner, isAdmin, username });
  });
});

// Edit profile page (GET)
// Edit profile page (GET)
app.get('/profile/edit/:username', isAuthenticated, (req, res) => {
  const userId = req.session.userId;

  // Get the user's current profile data
  db.get("SELECT id, username, email, password, bio, profile_picture FROM users WHERE id = ?", [userId], (err, user) => {
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
  const { username, email, password, bio, profile_picture } = req.body;
  const userId = req.session.userId;

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
        console.error('Error hashing password:', err);
        return res.status(500).send('Error hashing password');
    }

    // Update the user's profile in the database
     db.run("UPDATE users SET username = ?, email = ?, password = ?, bio = ?, profile_picture = ? WHERE id = ?",
         [username, email, hashedPassword, bio, profile_picture, userId], function(err) {
            if (err) {
                console.error('Error updating profile:', err);
               return res.status(500).send('Error updating profile');
           }

           console.log('Profile updated successfully');
           req.session.username = username;
            res.redirect(`/profile/${req.session.username}`); // Redirect back to the profile page
          });
  });
}); 

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
      if (err) return res.status(500).send('Error logging out');
      res.redirect('/login');
  });
});

// Delete profile (POST)
app.post('/profile/delete', isAuthenticated, (req, res) => {
  const userId = req.session.userId;

  // Delete the user from the database
  db.run("DELETE FROM users WHERE id = ?", [userId], function(err) {
      if (err) {
          console.error('Error deleting profile:', err);
          return res.status(500).send('Error deleting profile');
      }

      // Destroy the user's session after deleting the profile
      req.session.destroy((err) => {
          if (err) {
              console.error('Error destroying session:', err);
              return res.status(500).send('Error logging out');
          }

          console.log('Profile deleted successfully');
          res.redirect('/');  // Redirect to the homepage or login page after deletion
      });
  });
});

app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
  const query = "SELECT id, username, email, isAdmin FROM users";
  const username = req.session.username;
  const isAdmin = req.session.isAdmin;
  
  db.all(query, (err, users) => {
      if (err) {
          console.error('Error fetching users:', err);
          return res.status(500).send('Error fetching users');
      }

      res.render('admin', {
          users: users,
          currentUserId: req.session.userId,
          username,
          isAdmin
      });
  });
});

app.get('/users', (req, res) => {
    const query = "SELECT id, username, email, isAdmin FROM users";
    const username = req.session.username;
    const isAdmin = req.session.isAdmin || false;
    
    db.all(query, (err, users) => {
        if (err) {
            console.error('Error fetching users:', err);
            return res.status(500).send('Error fetching users');
        }
  
        res.render('users', {
            users: users,
            currentUserId: req.session.userId,
            username: username,
            isAdmin: isAdmin
        });
    });
  });

// Toggle admin status (POST)
app.post('/admin/toggle-admin/:id', isAuthenticated, isAdmin, (req, res) => {
  const userIdToToggle = req.params.id;
  const currentUserId = req.session.userId;

  if (userIdToToggle == currentUserId) {
      return res.status(400).send('You cannot change your own admin status.');
  }

  // Toggle the admin status for the specified user
  const query = "SELECT isAdmin FROM users WHERE id = ?";
  db.get(query, [userIdToToggle], (err, row) => {
      if (err) {
          console.error('Error fetching user:', err);
          return res.status(500).send('Error fetching user');
      }

      if (!row) {
          return res.status(404).send('User not found');
      }

      const newIsAdmin = row.isAdmin ? 0 : 1;  // Toggle the admin status

      const updateQuery = "UPDATE users SET isAdmin = ? WHERE id = ?";
      db.run(updateQuery, [newIsAdmin, userIdToToggle], function(err) {
          if (err) {
              console.error('Error updating user:', err);
              return res.status(500).send('Error updating user');
          }

          console.log(`User ${userIdToToggle} admin status updated to ${newIsAdmin}`);
          res.redirect('/admin');  // Redirect back to the admin panel
      });
  });
});

app.get('/admin/edit/:id', isAuthenticated, isAdmin, (req, res) => {
    const userId = req.params.id;

    // Fetch user details to pre-populate the form
    db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).send('Error fetching user');
        }

        if (!user) {
            return res.status(404).send('User not found');
        }

        // Render edit form and pass the user data to it
        res.render('edit-user', { user });
    });
});

// Admin Edit User Route (POST) - Save changes
app.post('/admin/edit/:id', isAuthenticated, isAdmin, (req, res) => {
    const userId = req.params.id;
    const { username, email, isAdmin } = req.body;

    // Update user data
    const query = `UPDATE users SET username = ?, email = ?, isAdmin = ? WHERE id = ?`;
    db.run(query, [username, email, isAdmin || 0, userId], function (err) {
        if (err) {
            console.error('Error updating user:', err);
            return res.status(500).send('Error updating user');
        }

        res.redirect('/admin');  // Redirect back to the admin panel after editing
    });
});

// Admin Delete User Route (POST)
app.post('/admin/delete/:id', isAuthenticated, isAdmin, (req, res) => {
    const userId = req.params.id;

    // Delete the user from the database
    const query = "DELETE FROM users WHERE id = ?";
    db.run(query, [userId], function (err) {
        if (err) {
            console.error('Error deleting user:', err);
            return res.status(500).send('Error deleting user');
        }

        res.redirect('/admin');  // Redirect back to the admin panel after deletion
    });
});

// Dont Remove
app.listen(3000, () => {
  console.log("Project is ready!");
});