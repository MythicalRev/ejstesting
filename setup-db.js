// setup-db.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./users.db'); // Create a database file if it doesn't exist

// Create a simple table called 'items'
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL, password TEXT NOT NULL, bio TEXT, profile_picture TEXT, isAdmin BOOLEAN)");

  // Insert some sample data
  const stmt = db.prepare("INSERT INTO users (username, email, password, bio, profile_picture, isAdmin) VALUES (?, ?, ?, ?, ?, ?)");
  stmt.run("testACC", "test@emailaddress.com", "testpass", "biohere", "/images/test.png", true);
  stmt.finalize();
});

db.close(() => {
  console.log('Database setup complete');
});
