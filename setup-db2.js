// setup-db.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./posts.db'); // Create a database file if it doesn't exist

// Create a simple table called 'items'
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, dir TEXT)");

  // Insert some sample data
  const stmt = db.prepare("INSERT INTO posts (dir) VALUES (?)");
  stmt.run("public/uploads/download.jpg");
  stmt.finalize();
});

db.close(() => {
  console.log('Database setup complete');
});
