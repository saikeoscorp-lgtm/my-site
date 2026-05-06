const { Resend } = require("resend");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const db = require("./db");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const multer = require("multer");

const deviceLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: "Too many requests" }
});

const app = express();

const uploadsDir = path.join(__dirname, "public", "uploads");

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    const safeExt = [".jpg", ".jpeg", ".png", ".webp", ".gif"].includes(ext)
      ? ext
      : ".png";

    cb(null, `${req.session.user.id}_${Date.now()}${safeExt}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 2 * 1024 * 1024
  },
  fileFilter: function (req, file, cb) {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Можно загружать только изображения"));
    }

    cb(null, true);
  }
});

const PORT = process.env.PORT || 3000;

const resend = new Resend(process.env.RESEND_API_KEY);

function makeCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    error: "Слишком много попыток входа. Попробуйте позже"
  }
});

const apiLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: {
    error: "Слишком много попыток входа. Попробуйте позже"
  }
});

app.use(session({
  secret: process.env.SESSION_SECRET || "curva_plyad_mat",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false
  }
}));
app.use("/private", (req, res, next) => {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }
  if (req.session.user.role !== "admin") {
    return res.status(403).send("Not asecss");
  }
  next();
});

app.use(express.static(path.join(__dirname, "public")));

function requireUserOrAdmin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Сначала войди в аккаунт" });
  }

  if (req.session.user.role !== "admin" && req.session.user.role !== "user" && req.session.user.role !== "device_user") {
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
    const code = makeCode();
    const expires = new Date(Date.now() + 10 * 60 * 1000);

    const result = await db.query(
      `
      INSERT INTO users
      (username, email, password_hash, role, is_verified, verification_code, verification_expires)
      VALUES ($1, $2, $3, $4, false, $5, $6)
      RETURNING id, email
      `,
      [username, email, password_hash, "user", code, expires]
    );

    try {
      console.log("SENDING EMAIL:", email, code);

      await resend.emails.send({
        from: "no-reply@korvin-base.ru",
        to: email,
        subject: "Код подтверждения Korvin Base",
        text: `Твой код подтверждения: ${code}`
      });

      console.log("EMAIL SENT OK");
    } catch (mailErr) {
      console.error("MAIL ERROR:", mailErr);
      return res.status(500).json({
        error: "Пользователь создан, но письмо не отправилось. Проверь Resend."
      });
    }

    res.json({
      message: "Регистрация успешна. Код отправлен на почту.",
      userId: result.rows[0].id
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(400).json({
        error: "Пользователь с таким логином или почтой уже существует"
      });
    }

    console.error("REGISTER ERROR:", err);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

app.post("/api/verify-email", async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: "Email и код обязательны" });
  }

  try {
    const result = await db.query(
      `
      SELECT id, verification_code, verification_expires
      FROM users
      WHERE email = $1
      `,
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    if (user.verification_code !== code) {
      return res.status(400).json({ error: "Неверный код" });
    }

    if (new Date(user.verification_expires) < new Date()) {
      return res.status(400).json({ error: "Код истёк" });
    }

    await db.query(
      `
      UPDATE users
      SET is_verified = true,
          verification_code = null,
          verification_expires = null
      WHERE id = $1
      `,
      [user.id]
    );

    res.json({ message: "Email подтверждён" });
  } catch (err) {
    console.error("VERIFY ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/login", loginLimiter, async (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
    return res.status(400).json({ error: "Введи логин/почту и пароль" });
  }

  try {
    const result = await db.query(
      `
      SELECT *
      FROM users
      WHERE username = $1 OR email = $1
      LIMIT 1
      `,
      [login]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: "Неверный логин или пароль" });
    }

    if (!user.is_verified) {
      return res.status(403).json({ error: "Подтверди email перед входом" });
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
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Вы вышли из аккаунта" });
  });
});

app.get("/api/me", async (req, res) => {
  if (!req.session.user) {
    return res.json({ user: null });
  }

  try {
    const result = await db.query(
      `
      SELECT id, username, email, role, bio,
             avatar_url, avatar_data,
             banner_url, banner_data
      FROM users
      WHERE id = $1
      `,
      [req.session.user.id]
    );

    res.json({ user: result.rows[0] || null });
  } catch (err) {
    console.error("ME ERROR:", err);
    res.status(500).json({ error: "Ошибка загрузки профиля" });
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
      "SELECT id, password_hash FROM users WHERE id = $1",
      [req.session.user.id]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password_hash);

    if (!isMatch) {
      return res.status(400).json({ error: "Старый пароль неверный" });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    await db.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [newHash, user.id]
    );

    res.json({ message: "Пароль изменён" });
  } catch (err) {
    console.error("CHANGE PASSWORD ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
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
    console.error("ADMIN ERROR:", err);
    res.status(500).json({ error: "Ошибка базы данных" });
  }
});

app.post("/api/admin/change-role", requireAdmin, async (req, res) => {
  const { userId, role } = req.body;

  if (!userId || !role) {
    return res.status(400).json({ error: "userId and role required" });
  }

  if (!["admin", "user", "viewer", "device_user"].includes(role)) {
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
    console.error("CHANGE ROLE ERROR:", err);
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
    console.error("DELETE USER ERROR:", err);
    res.status(500).json({ error: "Ошибка базы данных" });
  }
});

function getBearerToken(req) {
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return null;
  }

  return auth.slice(7);
}

async function requireApiAuth(req, res, next) {
  const token = getBearerToken(req);

  if (!token) {
    return res.status(401).json({ error: "Нет токена" });
  }

  try {
    const result = await db.query(
      `
      SELECT users.id, users.username, users.email, users.role
      FROM user_tokens
      JOIN users ON users.id = user_tokens.user_id
      WHERE user_tokens.token = $1
      AND user_tokens.expires_at > NOW()
      LIMIT 1
      `,
      [token]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: "Неверный токен" });
    }

    req.apiUser = user;
    next();
  } catch (err) {
    console.error("API AUTH ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
}

function requireApiAdmin(req, res, next) {
  if (!req.apiUser || req.apiUser.role !== "admin") {
    return res.status(403).json({ error: "Нет доступа" });
  }

  next();
}

app.post("/api/auth/login", apiLoginLimiter, async (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
    return res.status(400).json({ error: "Введи логин/почту и пароль" });
  }

  try {
    const result = await db.query(
      `
      SELECT *
      FROM users
      WHERE username = $1 OR email = $1
      LIMIT 1
      `,
      [login]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: "Неверный логин или пароль" });
    }

    if (!user.is_verified) {
      return res.status(403).json({ error: "Подтверди email перед входом" });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ error: "Неверный логин или пароль" });
    }

    const token = crypto.randomBytes(32).toString("hex");

    await db.query(
      `
      INSERT INTO user_tokens (user_id, token, expires_at)
      VALUES ($1, $2, NOW() + INTERVAL '30 days')
      `,
      [user.id, token]
    );

    res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error("API LOGIN ERROR:", err);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

app.get("/api/auth/me", requireApiAuth, async (req, res) => {
  res.json({ user: req.apiUser });
});

app.post("/api/auth/logout", requireApiAuth, async (req, res) => {
  const token = getBearerToken(req);

  await db.query(
    "DELETE FROM user_tokens WHERE token = $1",
    [token]
  );

  res.json({ ok: true, message: "Вы вышли" });
});

async function userCanAccessDevice(user, deviceId) {
  if (user.role === "device_user") {
    return true;
  }

  const result = await db.query(
    `
    SELECT id
    FROM devices
    WHERE device_id = $1 AND user_id = $2
    LIMIT 1
    `,
    [deviceId, user.id]
  );

  return result.rows.length > 0;
}

app.post("/api/device/register", requireApiAuth, async (req, res) => {
  const { deviceId, deviceToken } = req.body;

  if (!deviceId || !deviceToken) {
    return res.status(400).json({ error: "deviceId и deviceToken обязательны" });
  }

  if (req.apiUser.role !== "admin" && req.apiUser.role !== "viewer") {
    return res.status(403).json({ error: "Нет прав на привязку устройства" });
  }

  try {
    const existing = await db.query(
      "SELECT * FROM devices WHERE device_id = $1",
      [deviceId]
    );

    if (existing.rows.length > 0) {
      const device = existing.rows[0];

      if (device.user_id && device.user_id !== req.apiUser.id && req.apiUser.role !== "admin") {
        return res.status(403).json({ error: "Устройство уже привязано к другому пользователю" });
      }

      await db.query(
        `
        UPDATE devices
        SET user_id = $1,
            token = $2
        WHERE device_id = $3
        `,
        [req.apiUser.id, deviceToken, deviceId]
      );

      return res.json({ ok: true, message: "Устройство обновлено и привязано" });
    }

    await db.query(
      `
      INSERT INTO devices (device_id, token, user_id, status)
      VALUES ($1, $2, $3, 'offline')
      `,
      [deviceId, deviceToken, req.apiUser.id]
    );

    res.json({ ok: true, message: "Устройство создано и привязано" });
  } catch (err) {
    console.error("DEVICE REGISTER ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// ===== ESP API =====

app.get("/api/devices", requireApiAuth, async (req, res) => {
  try {
    let result;

   if (req.apiUser.role === "admin") {
  result = await db.query(`
    SELECT device_id, temperature, last_ping, user_id
    FROM devices
    ORDER BY device_id
  `);
} else if (req.apiUser.role === "device_user") {
  result = await db.query(`
    SELECT device_id, temperature, last_ping, user_id
    FROM devices
    WHERE user_id = $1
    ORDER BY device_id
  `, [req.apiUser.id]);
} else {
  return res.json({ devices: [] });
} 
    res.json({ devices: result.rows });
  } catch (err) {
    console.error("GET DEVICES ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/device/ping", deviceLimiter, async (req, res) => {
  const { deviceId, token, temperature, message } = req.body;

  if (!deviceId || !token) {
    return res.status(400).json({ error: "deviceId и token обязательны" });
  }

  try {
    const result = await db.query(
      "SELECT * FROM devices WHERE device_id = $1",
      [deviceId]
    );

    const device = result.rows[0];

    if (!device || device.token !== token) {
      return res.status(403).json({ error: "Неверный токен" });
    }

    // обновляем статус
    await db.query(
      `
      UPDATE devices
      SET status = 'online',
          temperature = $1,
          last_ping = NOW()
      WHERE device_id = $2
      `,
      [temperature || null, deviceId]
    );

    // лог
    if (message) {
      await db.query(
        `
        INSERT INTO device_logs (device_id, message)
        VALUES ($1, $2)
        `,
        [deviceId, message]
      );
    }

    res.json({ ok: true });

  } catch (err) {
    console.error("PING ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});


app.get("/api/device/status/:deviceId", requireApiAuth, async (req, res) => {
  const { deviceId } = req.params;

  try {
    const allowed = await userCanAccessDevice(req.apiUser, deviceId);

    if (!allowed) {
      return res.status(403).json({ error: "Нет доступа к устройству" });
    }

    const result = await db.query(
      "SELECT * FROM devices WHERE device_id = $1",
      [deviceId]
    );

    const device = result.rows[0];

    if (!device) {
      return res.status(404).json({ error: "Устройство не найдено" });
    }

    const online =
      device.last_ping &&
      new Date() - new Date(device.last_ping) < 30000;

    res.json({
      deviceId: device.device_id,
      online,
      temperature: device.temperature,
      lastPing: device.last_ping
    });
  } catch (err) {
    console.error("STATUS ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});


app.post("/api/device/command", requireApiAuth, async (req, res) => {
  const { deviceId, command } = req.body;

  if (!deviceId || !command) {
    return res.status(400).json({ error: "deviceId и command обязательны" });
  }

  if (req.apiUser.role !== "admin" &&req.apiUser.role !== "device_user") {
    return res.status(403).json({ error: "Нет прав на команды" });
  }

  try {
    const allowed = await userCanAccessDevice(req.apiUser, deviceId);

    if (!allowed) {
      return res.status(403).json({ error: "Нет доступа к устройству" });
    }

    await db.query(
      `
      INSERT INTO device_commands (device_id, command)
      VALUES ($1, $2)
      `,
      [deviceId, command]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error("COMMAND ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});


app.get("/api/device/commands/:deviceId", async (req, res) => {
  const { deviceId } = req.params;
  const { token } = req.query;

  try {
    const result = await db.query(
      "SELECT * FROM devices WHERE device_id = $1",
      [deviceId]
    );

    const device = result.rows[0];

    if (!device || device.token !== token) {
      return res.status(403).json({ error: "Неверный токен" });
    }

    const commands = await db.query(
      `
      SELECT id, command
      FROM device_commands
      WHERE device_id = $1 AND is_done = false
      ORDER BY id
      `,
      [deviceId]
    );

    // помечаем выполненными
    await db.query(
      `
      UPDATE device_commands
      SET is_done = true
      WHERE device_id = $1 AND is_done = false
      `,
      [deviceId]
    );

    res.json({ commands: commands.rows });

  } catch (err) {
    console.error("GET COMMANDS ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/api/device/logs/:deviceId", requireApiAuth, async (req, res) => {
  const { deviceId } = req.params;

  try {
    const allowed = await userCanAccessDevice(req.apiUser, deviceId);

    if (!allowed) {
      return res.status(403).json({ error: "Нет доступа к устройству" });
    }

    const result = await db.query(
      `
      SELECT message, created_at
      FROM device_logs
      WHERE device_id = $1
      ORDER BY created_at DESC
      LIMIT 50
      `,
      [deviceId]
    );

    res.json({ logs: result.rows });
  } catch (err) {
    console.error("DEVICE LOGS ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/api/admin/devices", requireAdmin, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT 
        devices.id,
        devices.device_id,
        devices.status,
        devices.temperature,
        devices.last_ping,
        devices.user_id,
        users.username,
        users.email
      FROM devices
      LEFT JOIN users ON users.id = devices.user_id
      ORDER BY devices.id
    `);

    res.json({ devices: result.rows });
  } catch (err) {
    console.error("ADMIN DEVICES ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/admin/unlink-device", requireAdmin, async (req, res) => {
  const { deviceId } = req.body;

  if (!deviceId) {
    return res.status(400).json({ error: "deviceId required" });
  }

  try {
    await db.query(
      `
      UPDATE devices
      SET user_id = NULL
      WHERE device_id = $1
      `,
      [deviceId]
    );

    res.json({ ok: true, message: "Устройство отвязано" });
  } catch (err) {
    console.error("UNLINK DEVICE ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/admin/device-command", requireAdmin, async (req, res) => {
  const { deviceId, command } = req.body;

  if (!deviceId || !command) {
    return res.status(400).json({ error: "deviceId и command обязательны" });
  }

  try {
    await db.query(
      `
      INSERT INTO device_commands (device_id, command)
      VALUES ($1, $2)
      `,
      [deviceId, command]
    );

    res.json({ ok: true, message: "Команда отправлена" });
  } catch (err) {
    console.error("ADMIN DEVICE COMMAND ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/api/admin/device-status/:deviceId", requireAdmin, async (req, res) => {
  const { deviceId } = req.params;

  try {
    const result = await db.query(
      "SELECT * FROM devices WHERE device_id = $1",
      [deviceId]
    );

    const device = result.rows[0];

    if (!device) {
      return res.status(404).json({ error: "Устройство не найдено" });
    }

    const online =
      device.last_ping &&
      new Date() - new Date(device.last_ping) < 30000;

    res.json({
      deviceId: device.device_id,
      online,
      temperature: device.temperature,
      lastPing: device.last_ping
    });
  } catch (err) {
    console.error("ADMIN DEVICE STATUS ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/api/public/profile/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const userResult = await db.query(
      `
      SELECT id, username, role, bio,
             avatar_url, avatar_data,
             banner_url, banner_data
      FROM users
      WHERE username = $1
      LIMIT 1
      `,
      [username]
    );

    const user = userResult.rows[0];

    if (!user) {
      return res.status(404).json({ error: "Профиль не найден" });
    }

    const achievementsResult = await db.query(
      `
      SELECT 
        achievements.code,
        achievements.title,
        achievements.description,
        achievements.icon_url,
        achievements.rarity,
        user_achievements.unlocked_at
      FROM user_achievements
      JOIN achievements ON achievements.id = user_achievements.achievement_id
      WHERE user_achievements.user_id = $1
      ORDER BY user_achievements.unlocked_at ASC
      `,
      [user.id]
    );

    delete user.id;

    res.json({
      user,
      achievements: achievementsResult.rows
    });
  } catch (err) {
    console.error("PUBLIC PROFILE ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});
app.get("/api/admin/device-logs/:deviceId", requireAdmin, async (req, res) => {
  const { deviceId } = req.params;

  try {
    const result = await db.query(
      `
      SELECT message, created_at
      FROM device_logs
      WHERE device_id = $1
      ORDER BY created_at DESC
      LIMIT 50
      `,
      [deviceId]
    );

    res.json({ logs: result.rows });
  } catch (err) {
    console.error("ADMIN DEVICE LOGS ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/profile/update", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Сначала войди в аккаунт" });
  }

  const {
    username,
    email,
    bio,
    avatar_url,
    avatar_data,
    banner_url,
    banner_data
  } = req.body;

  if (!username || !email) {
    return res.status(400).json({ error: "Логин и email обязательны" });
  }

  try {
    const result = await db.query(
      `
      UPDATE users
      SET username = $1,
          email = $2,
          bio = $3,
          avatar_url = $4,
          avatar_data = $5,
          banner_url = $6,
          banner_data = $7
      WHERE id = $8
      RETURNING id, username, email, role, bio,
                avatar_url, avatar_data,
                banner_url, banner_data
      `,
      [
        username,
        email,
        bio || "",
        avatar_url || "",
        avatar_data || "",
        banner_url || "",
        banner_data || "",
        req.session.user.id
      ]
    );

    const user = result.rows[0];

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    res.json({ message: "Профиль сохранён", user });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(400).json({ error: "Такой логин или email уже занят" });
    }

    console.error("PROFILE UPDATE ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/profile/upload-image", upload.single("image"), async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Сначала войди в аккаунт" });
  }

  const { type } = req.body;

  if (!req.file) {
    return res.status(400).json({ error: "Файл не загружен" });
  }

  if (type !== "avatar" && type !== "banner") {
    return res.status(400).json({ error: "Неверный тип изображения" });
  }

  const imagePath = "/uploads/" + req.file.filename;

  try {
    if (type === "avatar") {
      await db.query(
        `
        UPDATE users
        SET avatar_url = $1,
            avatar_data = ''
        WHERE id = $2
        `,
        [imagePath, req.session.user.id]
      );
    }

    if (type === "banner") {
      await db.query(
        `
        UPDATE users
        SET banner_url = $1,
            banner_data = ''
        WHERE id = $2
        `,
        [imagePath, req.session.user.id]
      );
    }

    res.json({
      ok: true,
      url: imagePath
    });
  } catch (err) {
    console.error("UPLOAD IMAGE ERROR:", err);
    res.status(500).json({ error: "Ошибка загрузки изображения" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server started on port ${PORT}`);
});
