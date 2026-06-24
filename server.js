/**
 * =============================================================================
 * FALSONIAC BANK — Servidor vulnerable de demostración académica
 * Propósito: Entorno controlado de ciberseguridad — NO usar en producción
 * =============================================================================
 *
 * Vulnerabilidades presentes:
 *  [1] SQL Injection  — /login, /account, /transaction/:id
 *  [2] IDOR           — /account?id=X, /transaction/:id, /movements
 *  [3] SSRF           — /api/fetch-rate
 *  [4] DDoS           — /api/report (sin rate-limit ni throttle)
 *  [5] MITM           — Cookies sin Secure ni HttpOnly; HTTP plano; CORS abierto
 */

const express    = require('express');
const sqlite3    = require('sqlite3').verbose();
const axios      = require('axios');
const path       = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// [VULN-MITM] CORS abierto: cualquier origen puede hacer peticiones autenticadas.
// En producción debería restringirse a dominios específicos.
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// ─── Base de datos ────────────────────────────────────────────────────────────

const db = new sqlite3.Database(path.join(__dirname, 'bank.db'));

function setupDatabase() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id       INTEGER PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT,        -- [VULN] contraseñas en texto plano
      role     TEXT,
      email    TEXT,
      phone    TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS accounts (
      id      INTEGER PRIMARY KEY,
      user_id INTEGER,
      balance REAL,
      label   TEXT,
      type    TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS transactions (
      id         INTEGER PRIMARY KEY,
      account_id INTEGER,
      amount     REAL,
      note       TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )`);

    db.get(`SELECT COUNT(*) AS count FROM users`, (err, row) => {
      if (err || (row && row.count > 0)) return;

      // Usuarios de prueba
      db.run(`INSERT INTO users (username, password, role, email, phone) VALUES ('alice',   'password123', 'customer', 'alice@falsoniac.com',   '987-111-001')`);
      db.run(`INSERT INTO users (username, password, role, email, phone) VALUES ('bob',     'secret456',   'customer', 'bob@falsoniac.com',     '987-222-002')`);
      db.run(`INSERT INTO users (username, password, role, email, phone) VALUES ('carlos',  'carlos2024',  'customer', 'carlos@falsoniac.com',  '987-333-003')`);
      db.run(`INSERT INTO users (username, password, role, email, phone) VALUES ('admin',   'adminpass',   'admin',    'admin@falsoniac.com',   '987-000-000')`);

      // Cuentas
      db.run(`INSERT INTO accounts (user_id, balance, label, type) VALUES (1,    4520.50,   'Cuenta Corriente',  'corriente')`);
      db.run(`INSERT INTO accounts (user_id, balance, label, type) VALUES (1,    1280.00,   'Cuenta de Ahorros', 'ahorros')`);
      db.run(`INSERT INTO accounts (user_id, balance, label, type) VALUES (2,   16200.75,   'Cuenta Corriente',  'corriente')`);
      db.run(`INSERT INTO accounts (user_id, balance, label, type) VALUES (3,    3050.00,   'Cuenta Corriente',  'corriente')`);
      db.run(`INSERT INTO accounts (user_id, balance, label, type) VALUES (4, 999999.99,    'Cuenta VIP',        'vip')`);

      // Movimientos
      db.run(`INSERT INTO transactions (account_id, amount, note) VALUES (1,  -120.00, 'Pago de servicio de luz')`);
      db.run(`INSERT INTO transactions (account_id, amount, note) VALUES (1,   500.00, 'Depósito en efectivo')`);
      db.run(`INSERT INTO transactions (account_id, amount, note) VALUES (1,  -250.00, 'Transferencia a Carlos')`);
      db.run(`INSERT INTO transactions (account_id, amount, note) VALUES (2,   300.00, 'Abono de nómina')`);
      db.run(`INSERT INTO transactions (account_id, amount, note) VALUES (3,   540.00, 'Depósito recibido')`);
      db.run(`INSERT INTO transactions (account_id, amount, note) VALUES (3,  -800.00, 'Retiro cajero')`);
      db.run(`INSERT INTO transactions (account_id, amount, note) VALUES (4,  -200.00, 'Pago proveedor')`);
      db.run(`INSERT INTO transactions (account_id, amount, note) VALUES (5, -9999.99, 'Transferencia internacional')`);
    });
  });
}

setupDatabase();

// =============================================================================
// RUTAS
// =============================================================================

// ─── Login ────────────────────────────────────────────────────────────────────
// [VULN-SQLi] La query se construye con concatenación directa de strings.
// Payload de ejemplo: usuario = ' OR '1'='1  →  bypassea la autenticación.
app.post('/login', (req, res) => {
  const username = req.body.username || '';
  const password = req.body.password || '';

  // ⚠ Concatenación directa — vulnerable a SQL Injection
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.get(sql, (err, user) => {
    if (err)  return res.status(500).json({ error: 'Error interno del servidor.' });
    if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });

    // [VULN-MITM] Cookie sin Secure ni HttpOnly → interceptable en tráfico HTTP
    //             y accesible desde JavaScript (document.cookie).
    res.cookie('falsoniac_session', user.username, {
      httpOnly: false,   // JS puede leerla → XSS viable
      secure:   false,   // Se envía por HTTP plano → MITM viable
      sameSite: 'Lax'
    });

    res.json({ success: true, username: user.username, role: user.role });
  });
});

// ─── Información del usuario autenticado ──────────────────────────────────────
app.get('/user-info', (req, res) => {
  const username = req.cookies.falsoniac_session || '';
  if (!username) return res.status(401).json({ error: 'Sin sesión activa.' });

  // [VULN-SQLi] username proviene de la cookie (no validada)
  const sql = `SELECT id, username, role, email, phone FROM users WHERE username = '${username}'`;

  db.get(sql, (err, user) => {
    if (err)  return res.status(500).json({ error: 'Error interno.' });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

    const acctSql = `SELECT id, balance, label, type FROM accounts WHERE user_id = ${user.id}`;
    db.all(acctSql, (acctErr, accounts) => {
      if (acctErr) return res.status(500).json({ error: 'Error al obtener cuentas.' });
      res.json({ user, accounts });
    });
  });
});

// ─── Ver cuenta por ID ────────────────────────────────────────────────────────
// [VULN-IDOR] No se verifica que la cuenta pertenezca al usuario en sesión.
// Cualquier usuario autenticado puede acceder a /account?id=3 (cuenta de otro).
app.get('/account', (req, res) => {
  const accountId = req.query.id;
  if (!accountId) return res.status(400).json({ error: 'Falta parámetro id.' });

  // ⚠ Sin verificación de ownership — vulnerable a IDOR
  const sql = `SELECT a.id, u.username, a.balance, a.label, a.type
               FROM accounts a JOIN users u ON a.user_id = u.id
               WHERE a.id = ${accountId}`;   // también sin parametrizar → SQLi

  db.get(sql, (err, account) => {
    if (err)     return res.status(500).json({ error: 'Error al buscar cuenta.' });
    if (!account) return res.status(404).json({ error: 'Cuenta no encontrada.' });
    res.json(account);
  });
});

// ─── Movimientos de una cuenta ────────────────────────────────────────────────
// [VULN-IDOR] Igual que /account: no verifica que la cuenta sea del usuario.
app.get('/movements', (req, res) => {
  const accountId = req.query.account_id;
  if (!accountId) return res.status(400).json({ error: 'Falta account_id.' });

  const sql = `SELECT id, amount, note, created_at FROM transactions
               WHERE account_id = ${accountId} ORDER BY id DESC`;

  db.all(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error al obtener movimientos.' });
    res.json(rows);
  });
});

// ─── Ver transacción individual ───────────────────────────────────────────────
// [VULN-IDOR + SQLi] ID no validado, sin verificación de pertenencia.
app.get('/transaction/:id', (req, res) => {
  const tid = req.params.id;
  const sql = `SELECT t.id, t.amount, t.note, t.created_at, a.label
               FROM transactions t JOIN accounts a ON t.account_id = a.id
               WHERE t.id = ${tid}`;

  db.get(sql, (err, tx) => {
    if (err) return res.status(500).json({ error: 'Error leyendo transacción.' });
    if (!tx)  return res.status(404).json({ error: 'Transacción no encontrada.' });
    res.json(tx);
  });
});

// ─── Transferencia ────────────────────────────────────────────────────────────
// [VULN-IDOR] Cualquier usuario puede transferir desde cualquier cuenta (from=X).
// No se valida que `from` pertenezca al usuario en sesión.
// [VULN-DoS]  Sin límite de monto ni rate-limit; solicitudes masivas agotan la DB.
app.post('/transfer', (req, res) => {
  const from   = req.body.from   || req.query.from;
  const to     = req.body.to     || req.query.to;
  const amount = parseFloat(req.body.amount || req.query.amount);
  const note   = req.body.note   || 'Transferencia';

  if (!from || !to || Number.isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Parámetros inválidos.' });
  }

  // ⚠ Sin verificar que `from` pertenece al usuario autenticado
  db.serialize(() => {
    db.run(`UPDATE accounts SET balance = balance - ${amount} WHERE id = ${from}`);
    db.run(`UPDATE accounts SET balance = balance + ${amount} WHERE id = ${to}`);
    db.run(`INSERT INTO transactions (account_id, amount, note) VALUES (${from}, -${amount}, '${note}')`);
    db.run(`INSERT INTO transactions (account_id, amount, note) VALUES (${to},   ${amount},  '${note}')`);
  });

  res.json({ success: true, message: `Transferencia de S/ ${amount.toFixed(2)} realizada.` });
});

// ─── Fetch de tipo de cambio (SSRF) ──────────────────────────────────────────
// [VULN-SSRF] El parámetro `source` es una URL arbitraria que el servidor solicita.
// Permite acceder a recursos internos: http://localhost:3000/account?id=5,
// metadatos de nube (http://169.254.169.254/), servicios internos, etc.
app.get('/api/fetch-rate', async (req, res) => {
  const source = req.query.source;
  if (!source) return res.status(400).json({ error: 'Falta parámetro source.' });

  // ⚠ Sin validación de dominio — vulnerable a SSRF
  try {
    const response = await axios.get(source, { timeout: 5000, responseType: 'text' });
    res.json({ url: source, data: response.data });
  } catch (err) {
    res.status(500).json({ error: `Error al consultar fuente: ${err.message}` });
  }
});

// ─── Reporte de estado del sistema (DDoS) ────────────────────────────────────
// [VULN-DoS] Endpoint sin rate-limit que ejecuta cálculo pesado en el hilo principal.
// Con muchas peticiones simultáneas colapsa el event loop de Node.js.
app.get('/api/report', (req, res) => {
  const depth = parseInt(req.query.depth, 10) || 5000000;

  // ⚠ Cálculo síncrono bloqueante — bloquea el event loop de Node.js
  let total = 0;
  for (let i = 0; i < depth; i++) {
    total += Math.sqrt(i) * Math.sin(i);
  }

  res.json({ status: 'ok', computed: total, depth });
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.get('/logout', (req, res) => {
  res.clearCookie('falsoniac_session');
  res.redirect('/login.html');
});

// ─── Perfil de sesión ─────────────────────────────────────────────────────────
// [VULN-MITM] Expone directamente el valor de la cookie en texto plano.
app.get('/api/profile', (req, res) => {
  const session = req.cookies.falsoniac_session || 'sin sesión';
  res.json({ session_cookie: session, note: 'Cookie accesible via JS (httpOnly=false)' });
});

// =============================================================================
app.listen(PORT, () => {
  console.log(`\n🏦  Falsoniac Bank escuchando en http://localhost:${PORT}`);
  console.log(`⚠   Aplicación VULNERABLE — sólo uso académico\n`);
});
