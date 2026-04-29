const nodemailer = require("nodemailer");

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

function makeCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

app.use(
session({
secret: "curva_plyad_mat",
resave: false,
saveUninitialized: false,
cookie: {
httpOnly: true,
sameSite: "lax",
secure: false
}
})
);

app.use(express.static(path.join(__dirname, "public")));

function requireUserOrAdmin(req, res, next) {
if (!req.session.user) {
return res.status(401).json({ error: "Сначала войди в аккаунт" });
}

if (req.session.user.role !== "admin" && req.session.user.role !== "user") {
return res.status(403).json({ error: "Нет доступа" });
}

next();
}

function requireAdmin(req, res, next) {
if (!req.session.user) {
return res.status(401).json({ error: "Сначала войди в аккаунт" });
}

if (req.session.user.role !== "admin") {
return res.status(403).json({ error: "Нет доступа" });
}

next();
}

app.post("/register", async (req, res) => {
const { username, email, password } = req.body;

if (!username || !email || !password) {
return res.status(400).json({ error: "Заполни все поля" });
}

try {
const password_hash = await bcrypt.hash(password, 10);

const result = await db.query(
`
INSERT INTO users (username, email, password_hash, role)
VALUES ($1, $2, $3, $4)
RETURNING id
`,
[username, email, password_hash, "user"]
);

res.json({
message: "Регистрация успешна",
userId: result.rows[0].id
});
} catch (err) {
if (err.code === "23505") {
return res.status(400).json({
error: "Пользователь с таким логином или почтой уже существует"
});
}

console.error(err);
res.status(500).json({ error: "Ошибка базы данных" });
}
});

app.post("/login", async (req, res) => {
const { login, password } = req.body;

if (!login || !password) {
return res.status(400).json({ error: "Введи логин/почту и пароль" });
}

try {
const result = await db.query(
`
SELECT * FROM users
WHERE username = $1 OR email = $1
LIMIT 1
`,
[login]
);

const user = result.rows[0];

if (!user) {
return res.status(401).json({ error: "Неверный логин или пароль" });
}

const isMatch = await bcrypt.compare(password, user.password_hash);

if (!isMatch) {
return res.status(401).json({ error: "Неверный логин или пароль" });
}

req.session.user = {
id: user.id,
username: user.username,
email: user.email,
role: user.role
};

res.json({
message: "Вход выполнен",
user: req.session.user
});
} catch (err) {
console.error(err);
res.status(500).json({ error: "Ошибка сервера" });
}
});

app.post("/api/logout", (req, res) => {
req.session.destroy(() => {
res.json({ message: "You is Log Out" });
});
});

app.get("/api/me", async (req, res) => {
  if (!req.session.user) {
    return res.json({ user: null });
  }

  try {
    const result = await db.query(
      "SELECT id, username, email, role, bio, avatar_url, avatar_data FROM users WHERE id = $1",
      [req.session.user.id]
    );

    res.json({ user: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ error: "Ошибка загрузки профиля" });
  }
});

app.post("/api/profile/update", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Сначала войди в аккаунт" });
  }

  const { username, email, bio, avatar_url, avatar_data } = req.body;

  try {
    const result = await db.query(
      `
      UPDATE users
      SET username = $1,
          email = $2,
          bio = $3,
          avatar_url = $4,
          avatar_data = $5
      WHERE id = $6
      RETURNING id, username, email, role, bio, avatar_url, avatar_data
      `,
      [
        username,
        email,
        bio || "",
        avatar_url || "",
        avatar_data || "",
        req.session.user.id
      ]
    );

    res.json({ message: "Профиль сохранён", user: result.rows[0] });
  } catch (err) {
    console.error("PROFILE UPDATE ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/profile.html", requireUserOrAdmin, (req, res) => {
res.sendFile(path.join(__dirname, "public", "private", "profile.html"));
});

app.get("/admin.html", requireAdmin, (req, res) => {
res.sendFile(path.join(__dirname, "public", "private", "admin.html"));
});

app.get("/docs.html", requireUserOrAdmin, (req, res) => {
res.sendFile(path.join(__dirname, "public", "private", "docs.html"));
});

app.get("/api/admin", requireAdmin, async (req, res) => {
try {
const result = await db.query(
"SELECT id, username, email, role FROM users ORDER BY id"
);

res.json({
message: "Welcome in admin panel",
user: req.session.user,
allUsers: result.rows
});
} catch (err) {
console.error(err);
res.status(500).json({ error: "Ошибка базы данных" });
}
});

app.post("/api/change-password", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Сначала войди в аккаунт" });
  }

  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: "Заполни все поля" });
  }

  if (newPassword.length < 5) {
    return res.status(400).json({ error: "Пароль слишком короткий" });
  }

  try {
    const result = await db.query(
      "SELECT password_hash FROM users WHERE id = $1",
      [req.session.user.id]
    );

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(oldPassword, user.password_hash);

    if (!isMatch) {
      return res.status(400).json({ error: "Старый пароль неверный" });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    await db.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [newHash, req.session.user.id]
    );

    res.json({ message: "Пароль изменён" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/admin/change-role", requireAdmin, async (req, res) => {
const { userId, role } = req.body;

if (!userId || !role) {
return res.status(400).json({ error: "userId and role required" });
}

if (!["admin", "user", "viewer"].includes(role)) {
return res.status(400).json({ error: "invalid role" });
}

try {
const result = await db.query(
`
UPDATE users
SET role = $1
WHERE id = $2
RETURNING id
`,
[role, userId]
);

if (result.rows.length === 0) {
return res.status(404).json({ error: "user not found" });
}

res.json({ message: "role updated" });
} catch (err) {
console.error(err);
res.status(500).json({ error: "Ошибка базы данных" });
}
});

app.post("/api/admin/delete-user", requireAdmin, async (req, res) => {
const { userId } = req.body;

if (!userId) {
return res.status(400).json({ error: "userId required" });
}

const id = Number(userId);

if (req.session.user && req.session.user.id === id) {
return res.status(400).json({ error: "you cannot delete yourself" });
}

try {
const result = await db.query(
`
DELETE FROM users
WHERE id = $1
RETURNING id
`,
[id]
);

if (result.rows.length === 0) {
return res.status(404).json({ error: "user not found" });
}

res.json({ message: "user deleted" });
} catch (err) {
console.error(err);
res.status(500).json({ error: "Ошибка базы данных" });
}
});

app.listen(PORT, "0.0.0.0", () => {
console.log(`Server started on port ${PORT}`);
});
