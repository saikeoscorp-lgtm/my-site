const db = require('./db');

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
  )
`, (err) => {
  if (err) {
    console.error('Ошибка создания таблицы users:', err.message);
  } else {
    console.log('Таблица users готова');
  }
});

db.close();