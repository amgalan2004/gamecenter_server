import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import morgan from "morgan";

dotenv.config();
const app = express();

/* =========================================================
   🧩 MIDDLEWARES
   ========================================================= */
app.use(cors({
  origin: [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://gamecenter-client.vercel.app"
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

// Preflight fix
app.use(cors());

app.use(express.json({ limit: "1mb" }));
app.use(helmet());
app.use(morgan("dev"));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api", apiLimiter);

/* =========================================================
   🗄️ DATABASE CONNECTION
   ========================================================= */
let db;

if (process.env.DATABASE_URL) {
  // 👉 ONLINE (Render + Railway)
  db = await mysql.createPool(process.env.DATABASE_URL);
  console.log("✅ Connected using DATABASE_URL (Production)");
} else {
  // 👉 LOCAL (XAMPP)
  db = await mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASS || "",
    database: process.env.DB_NAME || "gamecenter_db",
    port: Number(process.env.DB_PORT) || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  console.log("✅ Connected using Local MySQL");
}


const q = async (sql, params = []) => {
  try {
    const [rows] = await db.query(sql, params);
    return rows;
  } catch (err) {
    console.error("❌ DB QUERY ERROR:", err);
    throw err;
  }
};

/* =========================================================
   🧠 AUTH
   ========================================================= */
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: "Authentication token required" });

  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
};

const requireRoles = (...allowedRoles) => {
  return (req, res, next) => {
    const role = req.user?.role;
    if (!role || !allowedRoles.includes(role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
};

/* =========================================================
   🧾 REGISTER
   ========================================================= */
app.post("/api/auth/register", async (req, res) => {
  const conn = await db.getConnection();
  try {
    const {
      username,
      email,
      phone,
      password,
      role,
      location,
      center_name,
      latitude,
      longitude,
    } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Имэйл болон нууц үг шаардлагатай." });

    const exists = await q("SELECT id FROM users WHERE email = ?", [email]);
    if (exists.length)
      return res.status(409).json({ error: "Имэйл бүртгэлтэй байна." });

    const hash = await bcrypt.hash(password, 10);

    await conn.beginTransaction();

    const normalizedRole = role || "PLAYER";

    const [userResult] = await conn.query(
      "INSERT INTO users (username, email, phone, password_hash, role, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')",
      [
        normalizedRole === "CENTER_ADMIN"
          ? center_name || "Center Owner"
          : username || "Player",
        email,
        phone || null,
        hash,
        normalizedRole,
      ]
    );

    const userId = userResult.insertId;

    if (normalizedRole === "CENTER_ADMIN") {
      await conn.query(
        `INSERT INTO gamingcenters 
         (user_id, name, location, contact_info, working_hours, tariff, status, latitude, longitude)
         VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)`,
        [
          userId,
          center_name || "New Game Center",
          location || "Байршил тодорхойгүй",
          phone || email,
          "10:00 - 22:00",
          10000,
          latitude ?? 47.918873,
          longitude ?? 106.917701,
        ]
      );
    }

    await conn.commit();
    conn.release();

    const token = jwt.sign(
      { id: userId, role: normalizedRole },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
    );

    res.json({
      success: true,
      message: "Бүртгэл амжилттай.",
      token,
      user: { id: userId, email, role: normalizedRole },
    });
  } catch (err) {
    await conn.rollback();
    conn.release();
    console.error("❌ REGISTER ERROR:", err);
    res.status(500).json({ error: "Серверийн алдаа гарлаа." });
  }
});

/* =========================================================
   🔐 LOGIN
   ========================================================= */
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const [user] = await q("SELECT * FROM users WHERE email = ?", [email]);
    if (!user)
      return res.status(401).json({ error: "Имэйл эсвэл нууц үг буруу байна." });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid)
      return res.status(401).json({ error: "Имэйл эсвэл нууц үг буруу байна." });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
    );

    res.json({
      success: true,
      message: "Нэвтрэлт амжилттай.",
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        username: user.username,
      },
    });
  } catch (err) {
    console.error("❌ LOGIN ERROR:", err);
    res.status(500).json({ error: "Серверийн алдаа." });
  }
});

/* =========================================================
   🏢 CENTER_ADMIN — OWN CENTER INFO
   ========================================================= */
app.get("/api/center/my-center", authenticate, async (req, res) => {
  try {
    const [center] = await q("SELECT * FROM gamingcenters WHERE user_id = ?", [
      req.user.id,
    ]);
    if (!center) return res.status(404).json({ error: "Төв олдсонгүй." });
    res.json(center);
  } catch (err) {
    console.error("❌ CENTER FETCH ERROR:", err);
    res.status(500).json({ error: "Серверийн алдаа." });
  }
});

/* =========================================================
   ✅ ADMIN STATISTICS (REAL)
   - totalBookings: тухайн төвийн нийт захиалга
   - activePlayers: өнөөдөр захиалга хийсэн unique хэрэглэгч
   - todayRevenue: өнөөдрийн орлого (PAID)
   - status: төвийн төлөв
   ========================================================= */
app.get(
  "/api/admin/statistics",
  authenticate,
  requireRoles("CENTER_ADMIN", "OWNER"),
  async (req, res) => {
    try {
      // admin-ийн center авах
      const [center] = await q(
        "SELECT id, status FROM gamingcenters WHERE user_id = ?",
        [req.user.id]
      );
      if (!center) return res.status(404).json({ error: "Төв олдсонгүй." });

      const centerId = center.id;

      // Нийт захиалга
      const [totalRow] = await q(
        `SELECT COUNT(*) AS totalBookings
         FROM reservations r
         JOIN pcs p ON p.id = r.pc_id
         WHERE p.center_id = ?`,
        [centerId]
      );

      // Өнөөдрийн орлого (PAID)
      const [revRow] = await q(
        `SELECT COALESCE(SUM(r.total_price), 0) AS todayRevenue
         FROM reservations r
         JOIN pcs p ON p.id = r.pc_id
         WHERE p.center_id = ?
           AND DATE(r.created_at) = CURDATE()
           AND r.status = 'PAID'`,
        [centerId]
      );

      // Өнөөдөр идэвхтэй тоглогчид (unique)
      const [activeRow] = await q(
        `SELECT COUNT(DISTINCT r.user_id) AS activePlayers
         FROM reservations r
         JOIN pcs p ON p.id = r.pc_id
         WHERE p.center_id = ?
           AND DATE(r.created_at) = CURDATE()`,
        [centerId]
      );

      res.json({
        success: true,
        totalBookings: Number(totalRow?.totalBookings || 0),
        activePlayers: Number(activeRow?.activePlayers || 0),
        todayRevenue: Number(revRow?.todayRevenue || 0),
        status: center.status,
        centerId,
      });
    } catch (err) {
      console.error("❌ ADMIN STATS ERROR:", err);
      res.status(500).json({ error: "Статистик татахад алдаа гарлаа." });
    }
  }
);

/* =========================================================
   💻 PC MANAGEMENT
   ========================================================= */
app.get("/api/pcs/:centerId", authenticate, async (req, res) => {
  try {
    const { centerId } = req.params;
    const pcs = await q("SELECT * FROM pcs WHERE center_id = ?", [centerId]);
    res.json(pcs);
  } catch (err) {
    console.error("❌ FETCH PCs ERROR:", err);
    res.status(500).json({ error: "PC жагсаалт татахад алдаа гарлаа." });
  }
});

app.put("/api/pcs/update/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, seat_number, specs, status } = req.body;

    const result = await q(
      `UPDATE pcs 
       SET name = ?, seat_number = ?, specs = ?, status = ?, updated_at = NOW() 
       WHERE id = ?`,
      [name, seat_number || null, specs || "", status || "AVAILABLE", id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "PC олдсонгүй" });
    }

    const [updated] = await q("SELECT * FROM pcs WHERE id = ?", [id]);

    res.json({ success: true, message: "PC шинэчлэгдлээ", pc: updated });
  } catch (err) {
    console.error("❌ UPDATE PC ERROR:", err);
    res.status(500).json({ error: "PC шинэчлэх үед алдаа гарлаа." });
  }
});

app.delete("/api/pcs/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await q("DELETE FROM pcs WHERE id = ?", [id]);
    if (result.affectedRows === 0)
      return res.status(404).json({ error: "PC олдсонгүй" });
    res.json({ success: true, message: "PC устгагдлаа" });
  } catch (err) {
    console.error("❌ DELETE PC ERROR:", err);
    res.status(500).json({ error: "PC устгах үед алдаа гарлаа." });
  }
});

app.put("/api/center/update", authenticate, async (req, res) => {
  try {
    const { id, name, location, working_hours, tariff } = req.body;
    if (!id) return res.status(400).json({ error: "ID дутуу байна" });

    const result = await q(
      `UPDATE gamingcenters 
       SET name = ?, location = ?, working_hours = ?, tariff = ?, updated_at = NOW() 
       WHERE id = ? AND user_id = ?`,
      [name, location, working_hours, tariff, id, req.user.id]
    );

    if (result.affectedRows === 0)
      return res.status(404).json({ error: "Төв олдсонгүй эсвэл эрхгүй" });

    const [center] = await q("SELECT * FROM gamingcenters WHERE id = ?", [id]);

    res.json({ success: true, message: "Төвийн мэдээлэл шинэчлэгдлээ", center });
  } catch (err) {
    console.error("❌ UPDATE ERROR:", err);
    res.status(500).json({ error: "Өгөгдөл шинэчлэх үед алдаа гарлаа" });
  }
});

app.post("/api/pcs/add", authenticate, async (req, res) => {
  try {
    const { center_id, name, seat_number, specs, status } = req.body;
    if (!center_id || !name)
      return res.status(400).json({ error: "center_id эсвэл name дутуу байна." });

    await q(
      "INSERT INTO pcs (center_id, name, seat_number, specs, status) VALUES (?, ?, ?, ?, ?)",
      [center_id, name, seat_number || null, specs || "", status || "AVAILABLE"]
    );

    res.json({ success: true, message: "Шинэ PC амжилттай нэмэгдлээ." });
  } catch (err) {
    console.error("❌ ADD PC ERROR:", err);
    res.status(500).json({ error: "PC нэмэх үед алдаа гарлаа." });
  }
});

/* =========================================================
   📅 RESERVATIONS
   - давхцал шалгана
   - wallet lock
   - pc lock
   ========================================================= */
app.post("/api/reservations", authenticate, async (req, res) => {
  const conn = await db.getConnection();
  try {
    const userId = req.user.id;
    const { centerId, start_time, end_time, total_price } = req.body;

    if (!centerId || !start_time || !end_time || total_price === undefined) {
      conn.release();
      return res.status(400).json({ error: "Мэдээлэл дутуу байна." });
    }

    const start = new Date(start_time);
    const end = new Date(end_time);
    const totalPrice = Number(total_price);

    if (Number.isNaN(totalPrice) || totalPrice <= 0) {
      conn.release();
      return res.status(400).json({ error: "Үнэ буруу байна." });
    }
    if (!(start instanceof Date) || isNaN(start.getTime()) || isNaN(end.getTime()) || start >= end) {
      conn.release();
      return res.status(400).json({ error: "Цаг буруу байна." });
    }

    await conn.beginTransaction();

    // WALLET lock
    const [wrows] = await conn.query(
      "SELECT * FROM wallets WHERE user_id = ? FOR UPDATE",
      [userId]
    );
    if (!wrows.length || Number(wrows[0].balance) < totalPrice) {
      await conn.rollback();
      conn.release();
      return res.status(400).json({ error: "Wallet хүрэлцэхгүй" });
    }
    const wallet = wrows[0];

    // PC сонгох (AVAILABLE) + lock
    const [pcRows] = await conn.query(
      "SELECT id FROM pcs WHERE center_id = ? AND status = 'AVAILABLE' LIMIT 1 FOR UPDATE",
      [centerId]
    );

    if (!pcRows.length) {
      await conn.rollback();
      conn.release();
      return res.status(409).json({ error: "Сул PC алга" });
    }

    const pcId = pcRows[0].id;

    // Давхцал шалгах (энэ pc дээр тухайн хугацаанд захиалга байгаа эсэх)
    const [conflicts] = await conn.query(
      `SELECT id FROM reservations
       WHERE pc_id = ?
         AND status IN ('PAID','PENDING','CONFIRMED','BOOKED')
         AND (start_time < ? AND end_time > ?)
       LIMIT 1`,
      [pcId, end, start]
    );

    if (conflicts.length) {
      await conn.rollback();
      conn.release();
      return res.status(409).json({ error: "Энэ хугацаанд PC завгүй байна." });
    }

    // RESERVATION
    const [resInsert] = await conn.query(
      `INSERT INTO reservations
       (user_id, pc_id, start_time, end_time, total_price, status)
       VALUES (?, ?, ?, ?, ?, 'PAID')`,
      [userId, pcId, start, end, totalPrice]
    );

    const reservationId = resInsert.insertId;

    // PAYMENTS
    await conn.query(
      `INSERT INTO payments
       (booking_id, amount, payment_method, status)
       VALUES (?, ?, 'WALLET', 'SUCCEEDED')`,
      [reservationId, totalPrice]
    );

    // WALLET UPDATE
    await conn.query("UPDATE wallets SET balance = balance - ? WHERE id = ?", [
      totalPrice,
      wallet.id,
    ]);

    await conn.query(
      `INSERT INTO wallet_transactions
       (user_id, type, amount, description)
       VALUES (?, 'BOOKING', ?, ?)`,
      [userId, -totalPrice, `Reservation #${reservationId}`]
    );

    // PC STATUS
    await conn.query("UPDATE pcs SET status = 'BOOKED' WHERE id = ?", [pcId]);

    await conn.commit();
    conn.release();

    res.json({
      success: true,
      reservationId,
      status: "PAID",
      payment: "SUCCEEDED",
      totalPrice,
    });
  } catch (err) {
    await conn.rollback();
    conn.release();
    console.error("❌ RESERVATION ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

// My reservations
app.get("/api/reservations/my", authenticate, async (req, res) => {
  try {
    const rows = await q(
      `SELECT 
         r.*,
         p.name AS pc_name,
         g.name AS center_name,
         pay.status AS payment_status,
         pay.payment_method
       FROM reservations r
       LEFT JOIN pcs p ON r.pc_id = p.id
       LEFT JOIN gamingcenters g ON p.center_id = g.id
       LEFT JOIN payments pay ON pay.booking_id = r.id
       WHERE r.user_id = ?
       ORDER BY r.start_time DESC`,
      [req.user.id]
    );

    res.json(rows);
  } catch (err) {
    console.error("❌ FETCH MY RESERVATIONS ERROR:", err);
    res.status(500).json({ error: "Захиалгуудыг татахад алдаа гарлаа." });
  }
});

/* =========================================================
   🗺️ GET ALL CENTERS
   ========================================================= */
app.get("/api/centers", async (req, res) => {
  try {
    const centers = await q(
      "SELECT id, name, location, contact_info, working_hours, tariff, latitude, longitude, status FROM gamingcenters WHERE status != 'DELETED'"
    );
    res.json(centers);
  } catch (err) {
    console.error("❌ FETCH CENTERS ERROR:", err);
    res.status(500).json({ error: "Төвүүдийг татахад алдаа гарлаа." });
  }
});

/* =========================================================
   💰 WALLET API
   ========================================================= */
app.get("/api/wallet/me", authenticate, async (req, res) => {
  try {
    const userId = req.user.id;

    const [rows] = await db.query("SELECT * FROM wallets WHERE user_id = ?", [
      userId,
    ]);

    let wallet = rows[0];

    if (!wallet) {
      const [insertRes] = await db.query(
        "INSERT INTO wallets (user_id, balance) VALUES (?, 0.00)",
        [userId]
      );
      wallet = { id: insertRes.insertId, user_id: userId, balance: 0 };
    }

    res.json({ success: true, wallet });
  } catch (err) {
    console.error("❌ WALLET FETCH ERROR:", err);
    res.status(500).json({ error: "Түрийвчийн мэдээлэл татахад алдаа гарлаа." });
  }
});

app.post("/api/wallet/topup", authenticate, async (req, res) => {
  const conn = await db.getConnection();
  try {
    const userId = req.user.id;
    const { amount, method } = req.body;

    const amt = Number(amount);
    if (!amt || amt <= 0) {
      conn.release();
      return res.status(400).json({ error: "Дүн буруу байна." });
    }

    await conn.beginTransaction();

    const [rows] = await conn.query(
      "SELECT * FROM wallets WHERE user_id = ? FOR UPDATE",
      [userId]
    );

    let wallet = rows[0];
    if (!wallet) {
      const [insertRes] = await conn.query(
        "INSERT INTO wallets (user_id, balance) VALUES (?, 0.00)",
        [userId]
      );
      wallet = { id: insertRes.insertId, user_id: userId, balance: 0 };
    }

    const newBalance = Number(wallet.balance) + amt;

    await conn.query("UPDATE wallets SET balance = ? WHERE id = ?", [
      newBalance,
      wallet.id,
    ]);

    await conn.query(
      `INSERT INTO wallet_transactions (user_id, type, amount, description)
       VALUES (?, 'TOPUP', ?, ?)`,
      [userId, amt, method || "Wallet topup"]
    );

    await conn.commit();
    conn.release();

    res.json({ success: true, balance: newBalance });
  } catch (err) {
    await conn.rollback();
    conn.release();
    console.error("❌ WALLET TOPUP ERROR:", err);
    res.status(500).json({ error: "Түрийвч цэнэглэх үед алдаа гарлаа." });
  }
});

app.get("/api/wallet/transactions", authenticate, async (req, res) => {
  try {
    const userId = req.user.id;

    const tx = await q(
      `SELECT id, type, amount, description, created_at
       FROM wallet_transactions
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT 50`,
      [userId]
    );

    res.json({ success: true, transactions: tx });
  } catch (err) {
    console.error("❌ WALLET TX ERROR:", err);
    res.status(500).json({ error: "Гүйлгээний мэдээлэл татахад алдаа гарлаа." });
  }
});

/* =========================================================
   💥 GLOBAL ERROR HANDLER
   ========================================================= */
app.use((err, req, res, next) => {
  console.error("💥 GLOBAL ERROR:", err);
  res.status(500).json({ error: "Internal Server Error" });
});

/* =========================================================
   📊 ADMIN STATISTICS
   ========================================================= */
app.get("/api/admin/statistics", authenticate, async (req, res) => {
  try {
    // Нийт захиалга
    const [{ totalBookings }] = await q(
      "SELECT COUNT(*) AS totalBookings FROM reservations"
    );

    // Өнөөдрийн ашиг
    const [{ todayRevenue }] = await q(
      `SELECT IFNULL(SUM(total_price),0) AS todayRevenue
       FROM reservations
       WHERE DATE(created_at) = CURDATE()`
    );

    // Идэвхтэй тоглогчид (өнөөдөр захиалга хийсэн unique user)
    const [{ activePlayers }] = await q(
      `SELECT COUNT(DISTINCT user_id) AS activePlayers
       FROM reservations
       WHERE DATE(created_at) = CURDATE()`
    );

    res.json({
      totalBookings,
      activePlayers,
      todayRevenue,
      status: "APPROVED",
    });
  } catch (err) {
    console.error("❌ ADMIN STAT ERROR:", err);
    res.status(500).json({ error: "Статистик татахад алдаа гарлаа." });
  }
});

/* =========================================================
   📊 REPORTS (CENTER ADMIN)
   ========================================================= */
app.get("/api/reports/summary", authenticate, async (req, res) => {
  try {
    const userId = req.user.id;

    // админы төв
    const [center] = await q(
      "SELECT id FROM gamingcenters WHERE user_id = ?",
      [userId]
    );
    if (!center) {
      return res.status(404).json({ error: "Төв олдсонгүй" });
    }

    const centerId = center.id;

    // өнөөдөр
    const rows = await q(
      `
      SELECT
        COUNT(r.id)            AS total_bookings,
        IFNULL(SUM(r.total_price),0) AS total_income,
        COUNT(DISTINCT r.user_id) AS active_players
      FROM reservations r
      JOIN pcs p ON r.pc_id = p.id
      WHERE p.center_id = ?
        AND DATE(r.start_time) = CURDATE()
      `,
      [centerId]
    );

    res.json({
      success: true,
      report: rows[0],
    });
  } catch (err) {
    console.error("❌ REPORT ERROR:", err);
    res.status(500).json({ error: "Тайлан татах үед алдаа гарлаа" });
  }
});

// ================================
// 📊 PLATFORM STATISTICS API
// ================================
app.get("/api/stats/platform-stats", async (req, res) => {
  try {
    // Төвийн тоо
    const [centers] = await db.query(
      "SELECT COUNT(*) AS total FROM gaming_centers"
    );

    // Хэрэглэгчийн тоо
    const [users] = await db.query(
      "SELECT COUNT(*) AS total FROM users"
    );

    // Uptime (static for now)
    const uptime = 99.9;

    res.json({
      centers: centers[0].total,
      users: users[0].total,
      uptime: uptime,
    });
  } catch (err) {
    console.error("Platform stats error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/", (req, res) => {
  res.send("Gamecenter API is running 🚀");
});

/* =========================================================
   🚀 SERVER START
   ========================================================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
