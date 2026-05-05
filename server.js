const { Resend } = require("resend");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

const resend = new Resend(process.env.RESEND_API_KEY);

function makeCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

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

app.post("/login", async (req, res) => {
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
      SELECT id, username, email, role, bio, avatar_url, avatar_data
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

app.post("/api/profile/update", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Сначала войди в аккаунт" });
  }

  const { username, email, bio, avatar_url, avatar_data } = req.body;

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

// ===== ESP API =====

app.post("/api/device/ping", async (req, res) => {
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


app.get("/api/device/status/:deviceId", async (req, res) => {
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
    console.error("STATUS ERROR:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});


app.post("/api/device/command", async (req, res) => {
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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server started on port ${PORT}`);
});