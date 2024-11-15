// setup-db.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.db'); // Create a database file if it doesn't exist

// Create a simple table called 'items'
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, user TEXT, pass TEXT)");

  // Insert some sample data
  const stmt = db.prepare("INSERT INTO users (user, pass) VALUES (?, ?)");
  stmt.run("Mythical", "1234");
  stmt.finalize();
});

db.close(() => {
  console.log('Database setup complete');
});
