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

/* =========================================================
    🧩 SOCKET.IO & CORS CONFIG
   ========================================================= */
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
    📧 EMAIL CONFIGURATION & VERIFICATION STORAGE
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
    🗄️ DATABASE CONNECTION
   ========================================================= */
let db;
const initDB = async () => {
  try {
    const config = {
      host: process.env.DB_HOST || "localhost",
      user: process.env.DB_USER || "root",
      password: process.env.DB_PASS || "",
      database: process.env.DB_NAME || "gamecenter_db",
      port: Number(process.env.DB_PORT) || 3306,
      waitForConnections: true,
      connectionLimit: 10,
      timezone: '+08:00', 
    };
    db = await mysql.createPool(config);
    console.log("✅ Database Connected with UTC+8");
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
    🧠 AUTH MIDDLEWARES
   ========================================================= */
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token required" });
  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid token" });
  }
};

const isAccountantOrAdmin = (req, res, next) => {
  if (req.user && (req.user.role === 'ACCOUNTANT' || req.user.role === 'CENTER_ADMIN' || req.user.role === 'OWNER')) {
    next();
  } else {
    res.status(403).json({ error: "Энэ үйлдлийг хийх эрх танд байхгүй" });
  }
};

/* =========================================================
    🧾 AUTHENTICATION & VERIFICATION LOGIC
   ========================================================= */

app.post("/api/auth/send-verification", async (req, res) => {
  const { centerEmail } = req.body;
  try {
    const [admin] = await db.query(
      "SELECT u.id, g.name FROM users u JOIN gamingcenters g ON u.id = g.user_id WHERE u.email = ?", 
      [centerEmail]
    );
    if (!admin.length) {
      return res.status(404).json({ error: "Энэ имэйл хаягтай админ эсвэл PC төв олдсонгүй." });
    }
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    verificationCodes.set(centerEmail, { 
      code, 
      expires: Date.now() + 5 * 60 * 1000,
      centerId: admin[0].id 
    });
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: centerEmail,
      subject: "Санхүүч бүртгэлийн баталгаажуулах код",
      html: `<h2>Санхүүч бүртгэлийн баталгаажуулалт</h2><p>Код: <b>${code}</b></p>`,
    });
    res.json({ success: true, message: "Баталгаажуулах код илгээгдлээ." });
  } catch (error) {
    res.status(500).json({ error: "Имэйл илгээхэд алдаа гарлаа." });
  }
});

app.post("/api/auth/register", async (req, res) => {
  const conn = await db.getConnection();
  try {
    const { 
      username, email, phone, password, role, 
      location, center_name, centerEmail, 
      verificationCode, latitude, longitude 
    } = req.body;
    
    if (!email || !password) return res.status(400).json({ error: "Email and Password required" });

    if (role === "ACCOUNTANT") {
      const stored = verificationCodes.get(centerEmail);
      if (!stored || stored.code !== verificationCode || stored.expires < Date.now()) {
        return res.status(400).json({ error: "Баталгаажуулах код буруу эсвэл хугацаа дууссан байна." });
      }
    }

    const [exists] = await q("SELECT id FROM users WHERE email = ?", [email]);
    if (exists) return res.status(409).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    await conn.beginTransaction();

    const normalizedRole = role || "PLAYER";
    const [userResult] = await conn.query(
      "INSERT INTO users (username, email, phone, password_hash, role, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')",
      [normalizedRole === "CENTER_ADMIN" ? center_name : username || "User", email, phone, hash, normalizedRole]
    );

    const userId = userResult.insertId;
    await conn.query("INSERT INTO wallets (user_id, balance) VALUES (?, 0.00)", [userId]);

    if (normalizedRole === "CENTER_ADMIN") {
      await conn.query(
        "INSERT INTO gamingcenters (user_id, name, location, contact_info, status, working_hours, tariff, latitude, longitude) VALUES (?, ?, ?, ?, 'PENDING', '10:00-22:00', 10000, ?, ?)",
        [userId, center_name, location, email, latitude, longitude]
      );
    }
    
    if (role === "ACCOUNTANT") verificationCodes.delete(centerEmail);

    await conn.commit();
    const token = jwt.sign({ id: userId, role: normalizedRole }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, token, user: { id: userId, email, role: normalizedRole } });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: "Registration failed" });
  } finally {
    conn.release();
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const [user] = await q("SELECT * FROM users WHERE email = ?", [email]);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, token, user: { id: user.id, email: user.email, role: user.role, username: user.username } });
  } catch (err) {
    res.status(500).json({ error: "Login error" });
  }
});

/* =========================================================
    🏢 CENTER & PC MANAGEMENT
   ========================================================= */
app.get("/api/centers", async (req, res) => {
  const centers = await q("SELECT * FROM gamingcenters WHERE status != 'DELETED'");
  res.json(centers);
});

app.get("/api/centers/my-center", authenticate, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM gamingcenters WHERE user_id = ?", [req.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: "Төв олдсонгүй" });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

app.put("/api/centers/update/:id", authenticate, isAccountantOrAdmin, async (req, res) => {
  try {
    const { name, location, working_hours, tariff } = req.body;
    const centerId = req.params.id;

    const [result] = await db.query(
      "UPDATE gamingcenters SET name = ?, location = ?, working_hours = ?, tariff = ? WHERE id = ?",
      [name, location, working_hours, tariff, centerId]
    );

    if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Төв олдсонгүй эсвэл өөрчлөх эрхгүй байна" });
    }

    res.json({ 
      success: true, 
      message: "Төвийн тохиргоо амжилттай шинэчлэгдлээ" 
    });

  } catch (err) {
    console.error("Update Error:", err);
    res.status(500).json({ error: "Серверийн алдаа: Тохиргоо шинэчлэхэд алдаа гарлаа" });
  }
});

app.get("/api/pcs/:centerId", async (req, res) => {
  const pcs = await q("SELECT * FROM pcs WHERE center_id = ?", [req.params.centerId]);
  res.json(pcs);
});

app.post("/api/pcs/add", authenticate, async (req, res) => {
  try {
    const { name, seat_number, specs } = req.body;
    const [centers] = await db.query("SELECT id FROM gamingcenters WHERE user_id = ?", [req.user.id]);
    if (centers.length === 0) return res.status(404).json({ error: "Төв олдсонгүй." });

    const center_id = centers[0].id;
    const [result] = await db.query(
      "INSERT INTO pcs (center_id, name, seat_number, specs, status) VALUES (?, ?, ?, ?, 'AVAILABLE')",
      [center_id, name, seat_number, specs]
    );
    io.emit("status-changed", { centerId: center_id });
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: "PC нэмэхэд алдаа гарлаа" });
  }
});

/* =========================================================
    💰 FINANCE & STATS
   ========================================================= */

app.get("/api/finance/today-stats", authenticate, isAccountantOrAdmin, async (req, res) => {
  try {
    const [center] = await db.query("SELECT id FROM gamingcenters WHERE user_id = ?", [req.user.id]);
    if (!center.length) return res.status(404).json({ error: "Төв олдсонгүй" });
    const centerId = center[0].id;

    const [todayRes] = await db.query(
      "SELECT COUNT(*) as count FROM reservations r JOIN pcs p ON r.pc_id = p.id WHERE p.center_id = ? AND DATE(r.created_at) = CURDATE()",
      [centerId]
    );

    const [todayIncome] = await db.query(
      "SELECT SUM(r.total_price) as sum FROM reservations r JOIN pcs p ON r.pc_id = p.id WHERE p.center_id = ? AND (r.status = 'COMPLETED' OR r.status = 'PAID') AND DATE(r.created_at) = CURDATE()",
      [centerId]
    );

    const [todayExpense] = await db.query(
      "SELECT SUM(amount) as sum FROM expenses WHERE center_id = ? AND DATE(created_at) = CURDATE()",
      [centerId]
    );

    res.json({
      success: true,
      todayReservations: todayRes[0].count || 0,
      todayIncome: Number(todayIncome[0].sum) || 0,
      todayExpense: Number(todayExpense[0].sum) || 0
    });
  } catch (err) {
    res.status(500).json({ error: "Өнөөдрийн статистик татахад алдаа гарлаа" });
  }
});

app.get("/api/finance/summary", authenticate, isAccountantOrAdmin, async (req, res) => {
  try {
    const [incomeResult] = await db.query("SELECT SUM(total_price) as total FROM reservations WHERE status = 'COMPLETED' OR status = 'PAID'");
    const totalIncome = Number(incomeResult[0].total) || 0;

    const [expenseResult] = await db.query("SELECT SUM(amount) as total FROM expenses");
    const totalExpense = Number(expenseResult[0].total) || 0;

    const [dailyIncomeStats] = await db.query(`
      SELECT DATE_FORMAT(created_at, '%m-%d') as date, SUM(total_price) as daily_income
      FROM reservations WHERE status IN ('COMPLETED', 'PAID')
      GROUP BY DATE(created_at) ORDER BY created_at ASC
    `);

    const [recentTransactions] = await db.query(`
      (SELECT id, 'Захиалга' as description, total_price as amount, 'income' as type, created_at FROM reservations WHERE status IN ('COMPLETED', 'PAID'))
      UNION ALL
      (SELECT id, description, amount, 'expense' as type, created_at FROM expenses)
      ORDER BY created_at DESC
    `);

    res.json({
      success: true,
      totalIncome,
      totalExpense,
      netProfit: totalIncome - totalExpense,
      dailyStats: dailyIncomeStats,
      recentTransactions
    });
  } catch (err) {
    res.status(500).json({ error: "Санхүүгийн мэдээлэл татахад алдаа гарлаа" });
  }
});

app.post("/api/finance/expenses", authenticate, isAccountantOrAdmin, async (req, res) => {
  try {
    const { description, amount, category } = req.body;
    if (!description || !amount || !category) return res.status(400).json({ error: "Мэдээлэл дутуу" });

    const [center] = await db.query("SELECT id FROM gamingcenters WHERE user_id = ?", [req.user.id]);
    const centerId = center.length > 0 ? center[0].id : null;

    const [result] = await db.query(
      "INSERT INTO expenses (center_id, description, amount, category, created_at) VALUES (?, ?, ?, ?, NOW())",
      [centerId, description, amount, category]
    );
    io.emit("finance-updated");
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: "Зардал бүртгэхэд алдаа гарлаа" });
  }
});

app.get("/api/stats/platform-stats", authenticate, isAccountantOrAdmin, async (req, res) => {
  try {
    const [resCount] = await db.query("SELECT COUNT(*) as count FROM reservations");
    const [userCount] = await db.query("SELECT COUNT(*) as count FROM users");
    const [incomeSum] = await db.query("SELECT SUM(total_price) as sum FROM reservations WHERE status = 'COMPLETED' OR status = 'PAID'");
    const [centerCount] = await db.query("SELECT COUNT(*) as count FROM gamingcenters WHERE status IN ('ACTIVE', 'APPROVED')");

    res.json({
      success: true,
      totalReservations: resCount[0].count || 0,
      totalUsers: userCount[0].count || 0,
      totalIncome: Number(incomeSum[0].sum) || 0,
      totalCenters: centerCount[0].count || 0
    });
  } catch (err) {
    res.status(500).json({ error: "Статистик татахад алдаа гарлаа" });
  }
});

/* =========================================================
    📅 RESERVATIONS (ЗАСВАРЛАГДСАН)
   ========================================================= */
app.get("/api/reservations/my", authenticate, async (req, res) => {
  try {
    const [bookings] = await db.query(`
      SELECT r.*, p.name as pc_name, gc.name as center_name 
      FROM reservations r 
      JOIN pcs p ON r.pc_id = p.id 
      JOIN gamingcenters gc ON p.center_id = gc.id 
      WHERE r.user_id = ? ORDER BY r.created_at DESC
    `, [req.user.id]);
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ error: "Захиалгын түүх татахад алдаа гарлаа" });
  }
});

app.post("/api/reservations", authenticate, async (req, res) => {
  const conn = await db.getConnection();
  try {
    const { centerId, total_price, start_time, end_time } = req.body;
    let { pcId } = req.body; // Хэрэв client-аас pcId ирвэл ашиглана

    await conn.beginTransaction();

    // 1. Хэтэвч шалгах
    const [wallet] = await conn.query("SELECT balance FROM wallets WHERE user_id = ? FOR UPDATE", [req.user.id]);
    if (!wallet.length || Number(wallet[0].balance) < total_price) {
        throw new Error("Үлдэгдэл хүрэлцэхгүй байна");
    }

    // 2. Хэрэв pcId ирээгүй бол тухайн төвийн боломжтой эхний PC-г олох
    if (!pcId) {
        const [availablePcs] = await conn.query(
            "SELECT id FROM pcs WHERE center_id = ? AND status = 'AVAILABLE' LIMIT 1 FOR UPDATE", 
            [centerId]
        );
        if (!availablePcs.length) throw new Error("Боломжтой PC олдсонгүй");
        pcId = availablePcs[0].id;
    } else {
        // Хэрэв pcId ирсэн бол тэр нь AVAILABLE байгаа эсэхийг шалгах
        const [checkPc] = await conn.query(
            "SELECT id FROM pcs WHERE id = ? AND status = 'AVAILABLE' FOR UPDATE", 
            [pcId]
        );
        if (!checkPc.length) throw new Error("Сонгосон PC захиалгатай эсвэл олдсонгүй");
    }

    // 3. Захиалга бүртгэх
    const [resResult] = await conn.query(
      "INSERT INTO reservations (user_id, pc_id, start_time, end_time, total_price, status, created_at) VALUES (?, ?, ?, ?, ?, 'COMPLETED', NOW())",
      [req.user.id, pcId, start_time, end_time, total_price]
    );

    const bookingId = resResult.insertId;

    // 4. Төлбөр болон гүйлгээний түүх
    await conn.query("INSERT INTO payments (booking_id, amount, payment_method, status, created_at) VALUES (?, ?, 'WALLET', 'SUCCEEDED', NOW())", [bookingId, total_price]);
    await conn.query("INSERT INTO wallet_transactions (user_id, type, amount, description, created_at) VALUES (?, 'BOOKING', ?, ?, NOW())", [req.user.id, -total_price, `Захиалга #${bookingId}`]);
    
    // 5. Үлдэгдэл болон PC-н төлөв шинэчлэх
    await conn.query("UPDATE wallets SET balance = balance - ? WHERE user_id = ?", [total_price, req.user.id]);
    await conn.query("UPDATE pcs SET status = 'BOOKED' WHERE id = ?", [pcId]);

    await conn.commit();

    // Socket мэдэгдэл
    io.emit("status-changed", { pc_id: pcId, status: "BOOKED", centerId });
    io.emit("finance-updated"); 

    res.json({ 
        success: true, 
        balance: Number(wallet[0].balance) - total_price, 
        bookingId 
    });

  } catch (err) {
    await conn.rollback();
    console.error("Booking Error:", err.message);
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

/* =========================================================
    📊 WALLET & TRANSACTIONS
   ========================================================= */
app.get("/api/wallet/me", authenticate, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT balance FROM wallets WHERE user_id = ?", [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "Түрийвч олдсонгүй" });
    res.json({ success: true, wallet: { balance: Number(rows[0].balance) } });
  } catch (err) {
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
  } catch (err) {
    res.status(500).json({ error: "Гүйлгээний түүх татахад алдаа гарлаа" });
  }
});

app.post("/api/wallet/topup", authenticate, async (req, res) => {
  try {
    const { amount } = req.body;
    await db.query("UPDATE wallets SET balance = balance + ? WHERE user_id = ?", [amount, req.user.id]);
    await db.query("INSERT INTO wallet_transactions (user_id, type, amount, description, created_at) VALUES (?, 'TOPUP', ?, 'Цэнэглэлт', NOW())", [req.user.id, amount]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Цэнэглэхэд алдаа гарлаа" });
  }
});

/* =========================================================
    🚀 SERVER START
   ========================================================= */
const startServer = async () => {
  await initDB();
  
  io.on("connection", (socket) => {
    console.log("📡 User Connected:", socket.id);
  });

  const PORT = process.env.PORT || 5000;
  httpServer.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
};

startServer();