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
app.use(cors({ origin: process.env.CLIENT_URL || "*", credentials: true }));
app.use(express.json());
app.use(helmet());
app.use(morgan("dev"));

// 🚦 Rate limiter — brute-force халдлагаас хамгаалах
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
const db = await mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "gamecenter_db",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

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
   🧠 JWT AUTH MIDDLEWARE
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

/* =========================================================
   🧾 REGISTER (PLAYER / CENTER_ADMIN)
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

    // 🧍‍♂️ 1. Insert user
    const [userResult] = await conn.query(
      "INSERT INTO users (username, email, phone, password_hash, role, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')",
      [
        role === "CENTER_ADMIN" ? center_name || "Center Owner" : username,
        email,
        phone || null,
        hash,
        role || "PLAYER",
      ]
    );
    const userId = userResult.insertId;

    // 🏢 2. Insert center (if CENTER_ADMIN)
    if (role === "CENTER_ADMIN") {
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
          latitude || 47.918873,
          longitude || 106.917701,
        ]
      );
    }

    await conn.commit();
    conn.release();

    const token = jwt.sign({ id: userId, role }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || "7d",
    });

    res.json({
      success: true,
      message: "Бүртгэл амжилттай.",
      token,
      user: {
        id: userId,
        email,
        role: role || "PLAYER",
      },
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
    const [center] = await q(
      "SELECT * FROM gamingcenters WHERE user_id = ?",
      [req.user.id]
    );
    if (!center) return res.status(404).json({ error: "Төв олдсонгүй." });
    res.json(center);
  } catch (err) {
    console.error("❌ CENTER FETCH ERROR:", err);
    res.status(500).json({ error: "Серверийн алдаа." });
  }
});

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
// PC update
app.put("/api/pcs/update/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, seat_number, specs, status, center_id } = req.body;

    const result = await q(
      `UPDATE pcs SET name = ?, seat_number = ?, specs = ?, status = ?, updated_at = NOW() WHERE id = ?`,
      [name, seat_number || null, specs || "", status || "AVAILABLE", id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "PC олдсонгүй" });
    }

    // optionally return updated row
    const [updated] = await q("SELECT * FROM pcs WHERE id = ?", [id]);

    res.json({ success: true, message: "PC шинэчлэгдлээ", pc: updated });
  } catch (err) {
    console.error("❌ UPDATE PC ERROR:", err);
    res.status(500).json({ error: "PC шинэчлэх үед алдаа гарлаа." });
  }
});

// PC delete
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

// Center update (CENTER_ADMIN)
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
   🗺️ GET ALL CENTERS (for map)
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
   💥 GLOBAL ERROR HANDLER
   ========================================================= */
app.use((err, req, res, next) => {
  console.error("💥 GLOBAL ERROR:", err);
  res.status(500).json({ error: "Internal Server Error" });
});

/* =========================================================
   🚀 SERVER START
   ========================================================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
