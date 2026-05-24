import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import mysql from "mysql2/promise";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();
const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: {
    origin: ["http://localhost:5173", "http://localhost:3000", "http://localhost:4028", "https://gamecenter-client.vercel.app"],
    credentials: true
  }
});

app.use(cors({
  origin: ["http://localhost:5173", "http://localhost:3000", "http://localhost:4028", "https://gamecenter-client.vercel.app"],
  credentials: true
}));

app.use(express.json({ limit: "1mb" }));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan("dev"));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api", apiLimiter);

/* =========================================================
    📧 EMAIL CONFIG
   ========================================================= */
const verificationCodes = new Map();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/* =========================================================
    🗄️ DATABASE
   ========================================================= */
let db;
const initDB = async () => {
  try {
    db = await mysql.createPool({
      host: process.env.DB_HOST || "localhost",
      user: process.env.DB_USER || "root",
      password: process.env.DB_PASS || "",
      database: process.env.DB_NAME || "gamecenter_db",
      port: Number(process.env.DB_PORT) || 3306,
      waitForConnections: true,
      connectionLimit: 10,
      timezone: "+00:00",
    });
    console.log("✅ Database Connected");
  } catch (error) {
    console.error("❌ DB Connection Failed:", error);
    process.exit(1);
  }
};

const q = async (sql, params = []) => {
  const [rows] = await db.query(sql, params);
  return rows;
};

/* =========================================================
    🧠 MIDDLEWARES
   ========================================================= */
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token required" });
  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ error: "Invalid token" });
  }
};

const isAccountantOrAdmin = (req, res, next) => {
  const allowed = ["ACCOUNTANT", "CENTER_ADMIN", "OWNER", "SUPER_ADMIN"];
  if (req.user && allowed.includes(req.user.role)) {
    next();
  } else {
    res.status(403).json({ error: "Энэ үйлдлийг хийх эрх танд байхгүй" });
  }
};

// ✅ users.center_id баганаас шууд авна — хамгийн найдвартай арга
const getCenterId = async (user) => {
  if (user.role === "ACCOUNTANT") {
    const [rows] = await db.query(
      "SELECT center_id FROM users WHERE id = ? AND center_id IS NOT NULL",
      [user.id]
    );
    return rows.length ? rows[0].center_id : null;
  }
  // CENTER_ADMIN, OWNER
  const [rows] = await db.query(
    "SELECT id FROM gamingcenters WHERE user_id = ? LIMIT 1",
    [user.id]
  );
  return rows.length ? rows[0].id : null;
};

/* =========================================================
    🧾 AUTH ROUTES
   ========================================================= */

app.post("/api/auth/send-verification", async (req, res) => {
  const { centerEmail } = req.body;
  try {
    const [admins] = await db.query(
      "SELECT u.id, g.id as center_id, g.name FROM users u JOIN gamingcenters g ON u.id = g.user_id WHERE u.email = ?",
      [centerEmail]
    );
    if (!admins.length) {
      return res.status(404).json({ error: "Энэ имэйл хаягтай админ эсвэл PC төв олдсонгүй." });
    }
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    verificationCodes.set(centerEmail, {
      code,
      expires: Date.now() + 5 * 60 * 1000,
      centerId: admins[0].center_id, // ✅ center_id хадгалав
    });
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: centerEmail,
      subject: "Санхүүч бүртгэлийн баталгаажуулах код",
      html: `<h2>Санхүүч бүртгэлийн баталгаажуулалт</h2><p>Таны код: <b>${code}</b></p><p>Код 5 минутын дотор хүчинтэй.</p>`,
    });
    res.json({ success: true, message: "Баталгаажуулах код илгээгдлээ." });
  } catch (err) {
    console.error("send-verification error:", err);
    res.status(500).json({ error: "Имэйл илгээхэд алдаа гарлаа." });
  }
});

app.post("/api/auth/register", async (req, res) => {
  const conn = await db.getConnection();
  try {
    const { username, email, phone, password, role, location, center_name, centerEmail, verificationCode, latitude, longitude } = req.body;

    if (!email || !password) return res.status(400).json({ error: "Email and Password required" });

    if (role === "ACCOUNTANT") {
      const stored = verificationCodes.get(centerEmail);
      if (!stored || stored.code !== verificationCode || stored.expires < Date.now()) {
        return res.status(400).json({ error: "Баталгаажуулах код буруу эсвэл хугацаа дууссан байна." });
      }
    }

    const existing = await q("SELECT id FROM users WHERE email = ?", [email]);
    if (existing.length) return res.status(409).json({ error: "Энэ имэйл бүртгэлтэй байна" });

    const hash = await bcrypt.hash(password, 10);
    const normalizedRole = role || "PLAYER";
    const displayName = normalizedRole === "CENTER_ADMIN" ? center_name : (username || "User");

    await conn.beginTransaction();

    const [userResult] = await conn.query(
      "INSERT INTO users (username, email, phone, password_hash, role, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')",
      [displayName, email, phone, hash, normalizedRole]
    );
    const userId = userResult.insertId;

    await conn.query("INSERT INTO wallets (user_id, balance) VALUES (?, 0.00)", [userId]);

    if (normalizedRole === "CENTER_ADMIN") {
      await conn.query(
        "INSERT INTO gamingcenters (user_id, name, location, contact_info, status, working_hours, tariff, latitude, longitude) VALUES (?, ?, ?, ?, 'PENDING', '10:00-22:00', 10000, ?, ?)",
        [userId, center_name, location, email, latitude || null, longitude || null]
      );
    }

    // ✅ ACCOUNTANT бүртгэлд center_id хадгална
    if (normalizedRole === "ACCOUNTANT") {
      const stored = verificationCodes.get(centerEmail);
      if (stored?.centerId) {
        await conn.query(
          "UPDATE users SET center_id = ? WHERE id = ?",
          [stored.centerId, userId]
        );
      }
      verificationCodes.delete(centerEmail);
    }

    await conn.commit();

    const token = jwt.sign({ id: userId, role: normalizedRole }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, token, user: { id: userId, email, role: normalizedRole, username: displayName } });
  } catch (err) {
    await conn.rollback();
    console.error("Register Error:", err);
    res.status(500).json({ error: "Бүртгэл амжилтгүй болсон" });
  } finally {
    conn.release();
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and Password required" });

    const [user] = await q("SELECT * FROM users WHERE email = ?", [email]);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Имэйл эсвэл нууц үг буруу байна" });
    }
    if (user.status === "BANNED") {
      return res.status(403).json({ error: "Таны бүртгэл хориглогдсон байна" });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, token, user: { id: user.id, email: user.email, role: user.role, username: user.username } });
  } catch {
    res.status(500).json({ error: "Нэвтрэхэд алдаа гарлаа" });
  }
});

/* =========================================================
    🏢 CENTER & PC ROUTES
   ========================================================= */

app.get("/api/centers", async (req, res) => {
  try {
    const centers = await q("SELECT * FROM gamingcenters WHERE status NOT IN ('DELETED', 'DISABLED')");
    res.json(centers);
  } catch {
    res.status(500).json({ error: "Төвүүдийг татахад алдаа гарлаа" });
  }
});

app.get("/api/centers/my-center", authenticate, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM gamingcenters WHERE user_id = ?", [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "Төв олдсонгүй" });
    res.json(rows[0]);
  } catch {
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

app.put("/api/centers/update/:id", authenticate, isAccountantOrAdmin, async (req, res) => {
  try {
    const { name, location, working_hours, tariff } = req.body;
    const [result] = await db.query(
      "UPDATE gamingcenters SET name = ?, location = ?, working_hours = ?, tariff = ? WHERE id = ?",
      [name, location, working_hours, tariff, req.params.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: "Төв олдсонгүй" });
    res.json({ success: true, message: "Төвийн тохиргоо амжилттай шинэчлэгдлээ" });
  } catch {
    res.status(500).json({ error: "Тохиргоо шинэчлэхэд алдаа гарлаа" });
  }
});

app.get("/api/pcs/:centerId", async (req, res) => {
  try {
    const pcs = await q("SELECT * FROM pcs WHERE center_id = ?", [req.params.centerId]);
    res.json(pcs);
  } catch {
    res.status(500).json({ error: "PC жагсаалт татахад алдаа гарлаа" });
  }
});

app.post("/api/pcs/add", authenticate, async (req, res) => {
  try {
    const { name, seat_number, specs } = req.body;
    const [centers] = await db.query("SELECT id FROM gamingcenters WHERE user_id = ?", [req.user.id]);
    if (!centers.length) return res.status(404).json({ error: "Төв олдсонгүй." });
    const center_id = centers[0].id;
    const [result] = await db.query(
      "INSERT INTO pcs (center_id, name, seat_number, specs, status) VALUES (?, ?, ?, ?, 'AVAILABLE')",
      [center_id, name, seat_number, specs]
    );
    io.emit("status-changed", { centerId: center_id });
    res.json({ success: true, id: result.insertId });
  } catch {
    res.status(500).json({ error: "PC нэмэхэд алдаа гарлаа" });
  }
});

app.put("/api/pcs/update/:id", authenticate, async (req, res) => {
  try {
    const { name, seat_number, specs, status } = req.body;
    const [result] = await db.query(
      "UPDATE pcs SET name = ?, seat_number = ?, specs = ?, status = ? WHERE id = ?",
      [name, seat_number, specs, status || "AVAILABLE", req.params.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: "PC олдсонгүй" });
    io.emit("status-changed", { pc_id: Number(req.params.id), status });
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "PC шинэчлэхэд алдаа гарлаа" });
  }
});

app.delete("/api/pcs/delete/:id", authenticate, async (req, res) => {
  try {
    const [result] = await db.query("DELETE FROM pcs WHERE id = ?", [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: "PC олдсонгүй" });
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "PC устгахад алдаа гарлаа" });
  }
});

/* =========================================================
    💰 FINANCE ROUTES
   ========================================================= */

app.get("/api/finance/today-stats", authenticate, isAccountantOrAdmin, async (req, res) => {
  try {
    const centerId = await getCenterId(req.user);
    let todayResCount, todayIncomeSum, todayExpenseSum;

    if (centerId) {
      const [[r]] = await db.query(
        "SELECT COUNT(*) as count FROM reservations res JOIN pcs p ON res.pc_id = p.id WHERE p.center_id = ? AND DATE(res.created_at) = CURDATE()",
        [centerId]
      );
      const [[i]] = await db.query(
        "SELECT COALESCE(SUM(res.total_price), 0) as sum FROM reservations res JOIN pcs p ON res.pc_id = p.id WHERE p.center_id = ? AND res.status IN ('COMPLETED', 'PAID') AND DATE(res.created_at) = CURDATE()",
        [centerId]
      );
      const [[e]] = await db.query(
        "SELECT COALESCE(SUM(amount), 0) as sum FROM expenses WHERE center_id = ? AND DATE(created_at) = CURDATE()",
        [centerId]
      );
      todayResCount = r.count;
      todayIncomeSum = i.sum;
      todayExpenseSum = e.sum;
    } else {
      const [[r]] = await db.query("SELECT COUNT(*) as count FROM reservations WHERE DATE(created_at) = CURDATE()");
      const [[i]] = await db.query("SELECT COALESCE(SUM(total_price), 0) as sum FROM reservations WHERE status IN ('COMPLETED', 'PAID') AND DATE(created_at) = CURDATE()");
      const [[e]] = await db.query("SELECT COALESCE(SUM(amount), 0) as sum FROM expenses WHERE DATE(created_at) = CURDATE()");
      todayResCount = r.count;
      todayIncomeSum = i.sum;
      todayExpenseSum = e.sum;
    }

    res.json({
      success: true,
      todayReservations: todayResCount || 0,
      todayIncome: Number(todayIncomeSum) || 0,
      todayExpense: Number(todayExpenseSum) || 0,
    });
  } catch (err) {
    console.error("today-stats error:", err);
    res.status(500).json({ error: "Өнөөдрийн статистик татахад алдаа гарлаа" });
  }
});

app.get("/api/finance/summary", authenticate, isAccountantOrAdmin, async (req, res) => {
  try {
    const centerId = await getCenterId(req.user);
    let incomeResult, expenseResult, dailyStats, recentTransactions;

    if (centerId) {
      [[incomeResult]] = await db.query(
        `SELECT COALESCE(SUM(r.total_price), 0) as total
         FROM reservations r JOIN pcs p ON r.pc_id = p.id
         WHERE p.center_id = ? AND r.status IN ('COMPLETED', 'PAID')`,
        [centerId]
      );
      [[expenseResult]] = await db.query(
        "SELECT COALESCE(SUM(amount), 0) as total FROM expenses WHERE center_id = ?",
        [centerId]
      );
      [dailyStats] = await db.query(
        `SELECT DATE_FORMAT(r.created_at, '%m-%d') as date, SUM(r.total_price) as daily_income
         FROM reservations r JOIN pcs p ON r.pc_id = p.id
         WHERE p.center_id = ? AND r.status IN ('COMPLETED', 'PAID')
         GROUP BY DATE(r.created_at) ORDER BY r.created_at ASC`,
        [centerId]
      );
      [recentTransactions] = await db.query(
        `(SELECT r.id, 'Захиалга' as description, r.total_price as amount, 'income' as type, r.created_at
          FROM reservations r JOIN pcs p ON r.pc_id = p.id
          WHERE p.center_id = ? AND r.status IN ('COMPLETED', 'PAID'))
         UNION ALL
         (SELECT id, description, amount, 'expense' as type, created_at FROM expenses WHERE center_id = ?)
         ORDER BY created_at DESC LIMIT 20`,
        [centerId, centerId]
      );
    } else {
      [[incomeResult]] = await db.query("SELECT COALESCE(SUM(total_price), 0) as total FROM reservations WHERE status IN ('COMPLETED', 'PAID')");
      [[expenseResult]] = await db.query("SELECT COALESCE(SUM(amount), 0) as total FROM expenses");
      [dailyStats] = await db.query(
        `SELECT DATE_FORMAT(created_at, '%m-%d') as date, SUM(total_price) as daily_income
         FROM reservations WHERE status IN ('COMPLETED', 'PAID')
         GROUP BY DATE(created_at) ORDER BY created_at ASC`
      );
      [recentTransactions] = await db.query(
        `(SELECT id, 'Захиалга' as description, total_price as amount, 'income' as type, created_at
          FROM reservations WHERE status IN ('COMPLETED', 'PAID'))
         UNION ALL
         (SELECT id, description, amount, 'expense' as type, created_at FROM expenses)
         ORDER BY created_at DESC LIMIT 20`
      );
    }

    const totalIncome = Number(incomeResult.total) || 0;
    const totalExpense = Number(expenseResult.total) || 0;

    res.json({
      success: true,
      totalIncome,
      totalExpense,
      netProfit: totalIncome - totalExpense,
      dailyStats,
      recentTransactions,
    });
  } catch (err) {
    console.error("summary error:", err);
    res.status(500).json({ error: "Санхүүгийн мэдээлэл татахад алдаа гарлаа" });
  }
});

const addExpenseHandler = async (req, res) => {
  try {
    const { description, amount, category } = req.body;
    if (!description || !amount || !category)
      return res.status(400).json({ error: "Мэдээлэл дутуу" });

    const centerId = await getCenterId(req.user);
    if (!centerId) return res.status(400).json({ error: "Харьяа төв олдсонгүй" });

    const [result] = await db.query(
      "INSERT INTO expenses (center_id, description, amount, category, created_at) VALUES (?, ?, ?, ?, NOW())",
      [centerId, description, amount, category]
    );
    io.emit("finance-updated");
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    console.error("expense error:", err);
    res.status(500).json({ error: "Зардал бүртгэхэд алдаа гарлаа" });
  }
};
app.post("/api/finance/expenses", authenticate, isAccountantOrAdmin, addExpenseHandler);
app.post("/api/finance/add-expense", authenticate, isAccountantOrAdmin, addExpenseHandler);

app.get("/api/finance/reports", authenticate, isAccountantOrAdmin, async (req, res) => {
  try {
    const centerId = await getCenterId(req.user);
    if (!centerId) return res.status(404).json({ error: "Төв олдсонгүй" });
    const [reports] = await db.query(
      `SELECT r.*, p.name as pc_name FROM reservations r
       JOIN pcs p ON r.pc_id = p.id
       WHERE p.center_id = ? ORDER BY r.created_at DESC LIMIT 50`,
      [centerId]
    );
    res.json({ success: true, reports });
  } catch {
    res.status(500).json({ error: "Тайлан татахад алдаа гарлаа" });
  }
});

/* =========================================================
    📊 PLATFORM STATS
   ========================================================= */
app.get("/api/stats/platform-stats", authenticate, isAccountantOrAdmin, async (req, res) => {
  try {
    const [[resCount]] = await db.query("SELECT COUNT(*) as count FROM reservations");
    const [[userCount]] = await db.query("SELECT COUNT(*) as count FROM users");
    const [[incomeSum]] = await db.query("SELECT COALESCE(SUM(total_price), 0) as sum FROM reservations WHERE status IN ('COMPLETED', 'PAID')");
    const [[centerCount]] = await db.query("SELECT COUNT(*) as count FROM gamingcenters WHERE status IN ('ACTIVE', 'APPROVED')");

    res.json({
      success: true,
      totalReservations: resCount.count || 0,
      totalUsers: userCount.count || 0,
      totalIncome: Number(incomeSum.sum) || 0,
      totalCenters: centerCount.count || 0,
    });
  } catch (err) {
    console.error("platform-stats error:", err);
    res.status(500).json({ error: "Статистик татахад алдаа гарлаа" });
  }
});

/* =========================================================
    📅 RESERVATION ROUTES
   ========================================================= */

app.get("/api/reservations/my", authenticate, async (req, res) => {
  try {
    const [bookings] = await db.query(
      `SELECT r.*, p.name as pc_name, gc.name as center_name
       FROM reservations r
       JOIN pcs p ON r.pc_id = p.id
       JOIN gamingcenters gc ON p.center_id = gc.id
       WHERE r.user_id = ? ORDER BY r.created_at DESC`,
      [req.user.id]
    );
    res.json(bookings);
  } catch {
    res.status(500).json({ error: "Захиалгын түүх татахад алдаа гарлаа" });
  }
});

// ✅ Захиалга цуцлах
app.put("/api/reservations/:id/cancel", authenticate, async (req, res) => {
  const conn = await db.getConnection();
  try {
    const reservationId = req.params.id;

    // Захиалга байгаа эсэх + эзэмшигч мөн эсэхийг шалгана
    const [rows] = await conn.query(
      "SELECT r.*, p.center_id FROM reservations r JOIN pcs p ON r.pc_id = p.id WHERE r.id = ? AND r.user_id = ?",
      [reservationId, req.user.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Захиалга олдсонгүй" });
    }

    const reservation = rows[0];

    // Цаг эхлсэн бол цуцлах боломжгүй
    if (new Date(reservation.start_time) <= new Date()) {
      return res.status(400).json({ error: "Захиалгын цаг эхэлсэн тул цуцлах боломжгүй" });
    }

    // CANCELLED биш статустай байх ёстой
    if (reservation.status === "CANCELLED" || reservation.status === "AUTO_CANCELLED") {
      return res.status(400).json({ error: "Захиалга аль хэдийн цуцлагдсан байна" });
    }

    await conn.beginTransaction();

    // Захиалгыг CANCELLED болгоно
    await conn.query(
      "UPDATE reservations SET status = 'CANCELLED' WHERE id = ?",
      [reservationId]
    );

    // PC-г AVAILABLE болгоно
    await conn.query(
      "UPDATE pcs SET status = 'AVAILABLE' WHERE id = ?",
      [reservation.pc_id]
    );

    // Төлбөрийг буцаана (wallet-д нэмнэ)
    await conn.query(
      "UPDATE wallets SET balance = balance + ? WHERE user_id = ?",
      [reservation.total_price, req.user.id]
    );

    // Буцаалтын гүйлгээ бүртгэнэ
    await conn.query(
      "INSERT INTO wallet_transactions (user_id, type, amount, description, created_at) VALUES (?, 'REFUND', ?, ?, NOW())",
      [req.user.id, reservation.total_price, `Захиалга #${reservationId} цуцлалт - буцаалт`]
    );

    await conn.commit();

    // Real-time мэдэгдэл
    io.emit("status-changed", {
      pc_id: reservation.pc_id,
      status: "AVAILABLE",
      centerId: reservation.center_id,
    });

    res.json({
      success: true,
      message: `Захиалга цуцлагдлаа. ${Number(reservation.total_price).toLocaleString()}₮ буцааллаа.`,
      refundAmount: reservation.total_price,
    });
  } catch (err) {
    await conn.rollback();
    console.error("Cancel error:", err);
    res.status(500).json({ error: "Цуцлахад алдаа гарлаа" });
  } finally {
    conn.release();
  }
});

app.post("/api/reservations", authenticate, async (req, res) => {
  const conn = await db.getConnection();
  try {
    const { centerId, total_price, start_time, end_time } = req.body;
    let { pcId } = req.body;

    await conn.beginTransaction();

    if (!pcId) {
      const [availablePcs] = await conn.query(
        "SELECT id FROM pcs WHERE center_id = ? AND status = 'AVAILABLE' LIMIT 1 FOR UPDATE",
        [centerId]
      );
      if (!availablePcs.length) throw new Error("Боломжтой PC олдсонгүй");
      pcId = availablePcs[0].id;
    } else {
      const [checkPc] = await conn.query(
        "SELECT id FROM pcs WHERE id = ? AND status = 'AVAILABLE' FOR UPDATE",
        [pcId]
      );
      if (!checkPc.length) throw new Error("Сонгосон PC захиалгатай эсвэл олдсонгүй");
    }

    const [wallet] = await conn.query("SELECT balance FROM wallets WHERE user_id = ? FOR UPDATE", [req.user.id]);
if (!wallet.length || Number(wallet[0].balance) < total_price) {
  throw new Error("Үлдэгдэл хүрэлцэхгүй байна");
}

    await conn.query("UPDATE pcs SET status = 'BOOKED' WHERE id = ?", [pcId]);

    const [resResult] = await conn.query(
  "INSERT INTO reservations (user_id, pc_id, start_time, end_time, total_price, `status`, created_at) VALUES (?, ?, ?, ?, ?, 'PAID', NOW())",
  [req.user.id, pcId, start_time, end_time, total_price]
);

    await conn.query("UPDATE wallets SET balance = balance - ? WHERE user_id = ?", [total_price, req.user.id]);
// ✅ backtick нэмсэн:
await conn.query(
  "INSERT INTO wallet_transactions (user_id, `type`, amount, description, created_at) VALUES (?, 'BOOKING', ?, ?, NOW())",
  [req.user.id, total_price, `Reservation #${resResult.insertId}`]
);

    await conn.commit();
    io.emit("status-changed", { pc_id: pcId, status: "BOOKED", centerId });
    res.json({ success: true, message: "Захиалга амжилттай хийгдлээ", pc_id: pcId });
  } catch (err) {
    await conn.rollback();
    console.error("Booking Error:", err.message);
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

/* =========================================================
    💳 WALLET ROUTES
   ========================================================= */

app.get("/api/wallet/me", authenticate, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT balance FROM wallets WHERE user_id = ?", [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "Түрийвч олдсонгүй" });
    res.json({ success: true, wallet: { balance: Number(rows[0].balance) } });
  } catch {
    res.status(500).json({ error: "Түрийвч татахад алдаа гарлаа" });
  }
});

app.get("/api/wallet/transactions", authenticate, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT * FROM wallet_transactions WHERE user_id = ? ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json({ success: true, transactions: rows });
  } catch {
    res.status(500).json({ error: "Гүйлгээний түүх татахад алдаа гарлаа" });
  }
});

app.post("/api/wallet/topup", authenticate, async (req, res) => {
  const conn = await db.getConnection();
  try {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ error: "Зөв дүн оруулна уу" });

    await conn.beginTransaction();
    await conn.query("UPDATE wallets SET balance = balance + ? WHERE user_id = ?", [amount, req.user.id]);
    await conn.query(
      "INSERT INTO wallet_transactions (user_id, type, amount, description, created_at) VALUES (?, 'TOPUP', ?, 'Цэнэглэлт', NOW())",
      [req.user.id, amount]
    );
    await conn.commit();

    const [rows] = await db.query("SELECT balance FROM wallets WHERE user_id = ?", [req.user.id]);
    res.json({ success: true, balance: Number(rows[0]?.balance || 0) });
  } catch {
    await conn.rollback();
    res.status(500).json({ error: "Цэнэглэхэд алдаа гарлаа" });
  } finally {
    conn.release();
  }
});

/* =========================================================
    🚀 SERVER START
   ========================================================= */
const startServer = async () => {
  await initDB();

  io.on("connection", (socket) => {
    console.log("📡 User Connected:", socket.id);
    socket.on("disconnect", () => {
      console.log("📴 User Disconnected:", socket.id);
    });
  });

  const PORT = process.env.PORT || 5000;
  httpServer.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
};

startServer();