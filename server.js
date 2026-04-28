const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const db = require("./db");
const { error } = require("console");

const app = express();
const PORT =  process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
	console.log(`Server running on port ${PORT}`);
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
 session({
	secret: "curva_plyad_mat",
	resave: false,
	saveUninitialized: false,
	cookie: {
	 httpOnly: true,
	 sameSite: "lax",
	 secure: false,
	},
   })
);
app.use(express.static(path.join(__dirname, "public")));

function requireRole(...roles) {
 return (req, res, next) => {
   if (!req.session.user) {
     return res.status(401).json({ error: "Сначала войди в аккаунт" });
   }

   if (!roles.includes(req.session.user.role)) {
	return res.status(403).json({ error: "Нет доступа" });
   }

  next();
 };
}

//Registracion
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Заполни все поля' });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO users (username, email, password_hash, role)
      VALUES (?, ?, ?, ?)
    `;

    db.run(sql, [username, email, password_hash, 'user'], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Пользователь с таким логином или почтой уже существует' });
        }

        return res.status(500).json({ error: 'Ошибка базы данных' });
      }

      res.json({
        message: 'Регистрация успешна',
        userId: this.lastID
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

//Login in username or email
app.post('/login', (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
    return res.status(400).json({ error: 'Введи логин/почту и пароль' });
  }

  const sql = `
    SELECT * FROM users
    WHERE username = ? OR email = ?
  `;

  db.get(sql, [login, login], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    try {
      const isMatch = await bcrypt.compare(password, user.password_hash);

      if (!isMatch) {
        return res.status(401).json({ error: 'Неверный логин или пароль' });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      };

      res.json({
        message: 'Вход выполнен',
        user: req.session.user
      });
    } catch (error) {
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });
});

//Log out
app.post("/api/logout", (req, res) => {
	req.session.destroy(() => {
		res.json({ message: "You is Log Out" });
	});
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Сначала войди в аккаунт' });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Сначала войди в аккаунт' });
  }

  if (req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Нет доступа' });
  }

  next();
}

function requireUserOrAdmin(req, res, next) {
	if (!req.session.user) {
		return res.status(401).json({ error: 'Сначала войди в аккаунт'});
	}
	if (req.session.user.role !== 'admin' && req.session.user.role !== 'user') {
		return res.status(403).json({ error: 'Нет доступа'});
	}

	next();
}

//who is login now
app.get("/api/me", (req, res) => {
	if (!req.session.user) {
		return res.json({ user: null });
	}

	res.json({ user: req.session.user });
});

// Lock profile
app.get('/profile.html', requireUserOrAdmin, (req, res) => {
	res.sendFile(path.join(__dirname, 'public', 'private', 'profile.html'));
});

app.get('/admin.html', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'private', 'admin.html'));
});

app.get('/docs.html', requireUserOrAdmin, (req, res) => {
	res.sendFile(path.join(__dirname, 'public', 'private', 'docs.html'));
});

//Only admin
app.get("/api/admin", requireAdmin, (req, res) => {
  db.all(
    "SELECT id, username, email, role FROM users",
    [],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: "Ошибка базы данных" });
      }

      res.json({
        message: "Welcome in admin panel",
        user: req.session.user,
        allUsers: rows
      });
    }
  );
});

app.post("/api/admin/change-role", requireAdmin, (req, res) => {
  const { userId, role } = req.body;

  if (!userId || !role) {
    return res.status(400).json({ error: "userId and role required" });
  }

  if (!["admin", "user", "viewer"].includes(role)) {
    return res.status(400).json({ error: "invalid role" });
  }

  db.run(
    "UPDATE users SET role = ? WHERE id = ?",
    [role, userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: "Ошибка базы данных" });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: "user not found" });
      }

      res.json({ message: "role updated" });
    }
  );
});

app.post("/api/admin/delete-user", requireAdmin, (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: "userId required" });
  }

  const id = Number(userId);

  if (req.session.user && req.session.user.id === id) {
    return res.status(400).json({ error: "you cannot delete yourself" });
  }

  db.run(
    "DELETE FROM users WHERE id = ?",
    [id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: "Ошибка базы данных" });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: "user not found" });
      }

      res.json({ message: "user deleted" });
    }
  );
});

app.listen(PORT, "0.0.0.0", () => {
	console.log(`Server started: http://0.0.0.0:${PORT}`);
});
