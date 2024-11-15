// Values
const express = require("express");
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();

const db = new sqlite3.Database('./database.db');

let message = " ";

app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));

// You Can Add async By removing the /* And */
// You Can Change The / Its For {Link}/ Example {Link}/replit
app.get('/', (req, res) => {
  db.all("SELECT * FROM users", (err, rows) => {
    if (err) {
      console.error('Error fetching users:', err);
      res.status(500).send("Error fetching data from database");
    } else {
      // Pass both 'items' and 'message' to the EJS template
      res.render('home', { users: rows, message: message });
    }
  });
});

app.post('/change-variable', (req, res) => {
  const newValue = req.body.newValue;
  if (newValue) {
      req.session.message = newValue;  // Store the updated value in session
      console.log(newValue)
  } else {
      console.error('No new value received');
  }

  // Render the page again with the updated value
  res.redirect('/');
});

app.post('/add-item', (req, res) => {
  console.log(req.body)
  const user = req.body.username;
  const pass = req.body.password;
  if (user && pass) {
    db.run("INSERT INTO users (user, pass) VALUES (?,?)", [user, pass], function (err) {
      if (err) {
        res.status(500).send("Error adding item to database");
      } else {
        // Redirect back to the home page after adding the item
        res.redirect('/');
      }
    });
  } else {
    res.status(400).send("username or password is required");
  }
});

function getUserFromDb(usern, passw, callback) {
  db.get("SELECT * FROM users WHERE user = ? AND pass = ?", [usern, passw], (err, row) => {
    if (err) {
      console.error('Error fetching user:', err.message);
      callback(null);
    } else {
      callback(row); // Returns the user row
    }
  });
}

// Helper function to delete a user
function deleteUserFromDb(usern, passw, callback) {
  db.run("DELETE FROM users WHERE user = ? AND pass = ?", [usern, passw], function (err) {
    if (err) {
      console.error('Error deleting user:', err.message);
      callback(false); // No rows were deleted
    } else {
      callback(this.changes > 0); // Returns true if a user was deleted
    }
  });
}

// Route to handle user deletion
app.post('/remove-item', (req, res) => {
  const { usern, passw } = req.body;

  console.log(req.body)
  console.log(usern + " " + passw)

  if (!usern || !passw) {
    message = "Missing username or password."
  }

  // Check if the user exists
  getUserFromDb(usern, passw, (user) => {
    if (user) {
      // Try to delete the user
      deleteUserFromDb(usern, passw, (deleted) => {
        if (deleted) {
          message = "User deleted successfully";
        } else {
          message = "No user was deleted, check if user exists or retry";
        }
      });
    } else {
      message = "User not found."
    }
  });
  res.redirect("/")
});

// Dont Remove
app.listen(3000, () => {
  console.log("Project is ready!");
});