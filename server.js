/**
 * =============================================================================
 * FALSONIAC BANK — Servidor vulnerable de demostración académica
 * Propósito: Entorno controlado de ciberseguridad — NO usar en producción
 * Base de datos: MySQL (mysql2)
 * =============================================================================
 *
 * Vulnerabilidades presentes:
 *  [1] SQL Injection  — /login, /account, /transaction/:id, /movements
 *  [2] IDOR           — /account?id=X, /transaction/:id, /movements
 *  [3] SSRF           — /api/fetch-rate
 *  [4] DDoS           — /api/report (sin rate-limit ni throttle)
 *  [5] MITM           — Cookies sin Secure ni HttpOnly; HTTP plano; CORS abierto
 *
 * Configuración de conexión MySQL — editar las variables de entorno o el
 * objeto `dbConfig` a continuación antes de ejecutar.
 * =============================================================================
 */

const express      = require('express');
const mysql        = require('mysql2');
const axios        = require('axios');
const path         = require('path');
const bodyParser   = require('body-parser');
const cookieParser = require('cookie-parser');

const app  = express();
const PORT = process.env.PORT || 3000;

// =============================================================================
// CONFIGURACIÓN DE BASE DE DATOS MYSQL
// Puedes sobreescribir cualquier valor con variables de entorno:
//   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
// =============================================================================
const dbConfig = {
  host:     process.env.DB_HOST     || 'localhost',
  port:     process.env.DB_PORT     || 3306,
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASSWORD || 'root',
  database: process.env.DB_NAME     || 'falsoniac_bank',
  waitForConnections: true,
  connectionLimit:    10,
  queueLimit:         0
};

// Pool de conexiones MySQL
const pool = mysql.createPool(dbConfig);

/**
 * Ejecuta una query y devuelve una Promise con las filas.
 * Se usa pool.query directamente (sin prepared statements)
 * para mantener las vulnerabilidades de SQLi intactas.
 */
function query(sql, params) {
  return new Promise((resolve, reject) => {
    // NOTA: cuando `params` está presente se usa interpolación manual
    // para conservar la vulnerabilidad SQLi; NO se usan placeholders.
    pool.query(sql, (err, results) => {
      if (err) return reject(err);
      resolve(results);
    });
  });
}

// =============================================================================
// MIDDLEWARE
// =============================================================================

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// [VULN-MITM] CORS completamente abierto — permite peticiones desde cualquier origen.
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// =============================================================================
// RUTAS
// =============================================================================

// ─── Login ───────────────────────────────────────────────────────────────────
// [VULN-SQLi] La query se construye con concatenación directa de strings.
// Payload: usuario = ' OR '1'='1' -- (bypassea autenticación)
app.post('/login', async (req, res) => {
  const username = req.body.username || '';
  const password = req.body.password || '';

  // ⚠ Concatenación directa — vulnerable a SQL Injection
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  try {
    const rows = await query(sql);
    const user = rows[0];

    if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });

    // [VULN-MITM] Cookie sin Secure ni HttpOnly → interceptable en HTTP y legible desde JS
    res.cookie('falsoniac_session', user.username, {
      httpOnly: false,  // JS puede leerla → XSS viable
      secure:   false,  // Sin TLS → MITM viable
      sameSite: 'Lax'
    });

    res.json({ success: true, username: user.username, role: user.role });
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor.', detail: err.message });
  }
});

// ─── Información del usuario autenticado ─────────────────────────────────────
app.get('/user-info', async (req, res) => {
  const username = req.cookies.falsoniac_session || '';
  if (!username) return res.status(401).json({ error: 'Sin sesión activa.' });

  // [VULN-SQLi] username viene de la cookie sin validar
  const userSql = `SELECT id, username, role, email, phone FROM users WHERE username = '${username}'`;

  try {
    const users = await query(userSql);
    const user  = users[0];
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

    const acctSql  = `SELECT id, balance, label, type FROM accounts WHERE user_id = ${user.id}`;
    const accounts = await query(acctSql);

    res.json({ user, accounts });
  } catch (err) {
    res.status(500).json({ error: 'Error interno.', detail: err.message });
  }
});

// ─── Ver cuenta por ID ────────────────────────────────────────────────────────
// [VULN-IDOR] No se verifica que la cuenta pertenezca al usuario en sesión.
// [VULN-SQLi] El parámetro id se interpola directamente en la query.
app.get('/account', async (req, res) => {
  const accountId = req.query.id;
  if (!accountId) return res.status(400).json({ error: 'Falta parámetro id.' });

  // ⚠ Sin verificación de ownership y sin parametrizar
  const sql = `SELECT a.id, u.username, a.balance, a.label, a.type
               FROM accounts a JOIN users u ON a.user_id = u.id
               WHERE a.id = ${accountId}`;

  try {
    const rows    = await query(sql);
    const account = rows[0];
    if (!account) return res.status(404).json({ error: 'Cuenta no encontrada.' });
    res.json(account);
  } catch (err) {
    res.status(500).json({ error: 'Error al buscar cuenta.', detail: err.message });
  }
});

// ─── Movimientos de una cuenta ────────────────────────────────────────────────
// [VULN-IDOR] Sin verificación de que la cuenta pertenece al usuario.
app.get('/movements', async (req, res) => {
  const accountId = req.query.account_id;
  if (!accountId) return res.status(400).json({ error: 'Falta account_id.' });

  // ⚠ Sin parametrizar y sin chequeo de ownership
  const sql = `SELECT id, amount, note, created_at FROM transactions
               WHERE account_id = ${accountId} ORDER BY id DESC`;

  try {
    const rows = await query(sql);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener movimientos.', detail: err.message });
  }
});

// ─── Transacción individual ───────────────────────────────────────────────────
// [VULN-IDOR + SQLi]
app.get('/transaction/:id', async (req, res) => {
  const tid = req.params.id;

  const sql = `SELECT t.id, t.amount, t.note, t.created_at, a.label
               FROM transactions t JOIN accounts a ON t.account_id = a.id
               WHERE t.id = ${tid}`;

  try {
    const rows = await query(sql);
    const tx   = rows[0];
    if (!tx) return res.status(404).json({ error: 'Transacción no encontrada.' });
    res.json(tx);
  } catch (err) {
    res.status(500).json({ error: 'Error leyendo transacción.', detail: err.message });
  }
});

// ─── Transferencia ────────────────────────────────────────────────────────────
// [VULN-IDOR] No se verifica que `from` pertenezca al usuario autenticado.
// [VULN-DoS]  Sin rate-limit ni validación de monto máximo.
app.post('/transfer', async (req, res) => {
  const from   = req.body.from   || req.query.from;
  const to     = req.body.to     || req.query.to;
  const amount = parseFloat(req.body.amount || req.query.amount);
  const note   = req.body.note   || 'Transferencia';

  if (!from || !to || Number.isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Parámetros inválidos.' });
  }

  try {
    // ⚠ Sin verificar ownership de `from`; sin transacción atómica protegida
    await query(`UPDATE accounts SET balance = balance - ${amount} WHERE id = ${from}`);
    await query(`UPDATE accounts SET balance = balance + ${amount} WHERE id = ${to}`);
    await query(`INSERT INTO transactions (account_id, amount, note) VALUES (${from}, -${amount}, '${note}')`);
    await query(`INSERT INTO transactions (account_id, amount, note) VALUES (${to},   ${amount},  '${note}')`);

    res.json({ success: true, message: `Transferencia de S/ ${amount.toFixed(2)} realizada.` });
  } catch (err) {
    res.status(500).json({ error: 'Error en transferencia.', detail: err.message });
  }
});

// ─── Tipo de cambio / SSRF ────────────────────────────────────────────────────
// [VULN-SSRF] El servidor solicita cualquier URL que el usuario indique,
// permitiendo acceso a recursos internos (localhost, 169.254.169.254, etc.).
app.get('/api/fetch-rate', async (req, res) => {
  const source = req.query.source;
  if (!source) return res.status(400).json({ error: 'Falta parámetro source.' });

  // ⚠ Sin validación de dominio — SSRF directo
  try {
    const response = await axios.get(source, { timeout: 5000, responseType: 'text' });
    res.json({ url: source, data: response.data });
  } catch (err) {
    res.status(500).json({ error: `Error al consultar fuente: ${err.message}` });
  }
});

// ─── Reporte del sistema / DoS ────────────────────────────────────────────────
// [VULN-DoS] Bucle síncrono bloqueante en el event loop de Node.js.
// Sin rate-limit: peticiones masivas paralizan el servidor.
app.get('/api/report', (req, res) => {
  const depth = parseInt(req.query.depth, 10) || 5000000;

  // ⚠ Cálculo síncrono — bloquea el event loop mientras se ejecuta
  let total = 0;
  for (let i = 0; i < depth; i++) {
    total += Math.sqrt(i) * Math.sin(i);
  }

  res.json({ status: 'ok', computed: total, depth });
});

// ─── Perfil de sesión ─────────────────────────────────────────────────────────
// [VULN-MITM] Expone el valor de la cookie en texto plano como respuesta JSON.
app.get('/api/profile', (req, res) => {
  const session = req.cookies.falsoniac_session || 'sin sesión';
  res.json({
    session_cookie: session,
    note: 'Cookie accesible vía JS porque httpOnly=false'
  });
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.get('/logout', (req, res) => {
  res.clearCookie('falsoniac_session');
  res.redirect('/login.html');
});

// =============================================================================
// INICIO DEL SERVIDOR
// =============================================================================
pool.getConnection((err, connection) => {
  if (err) {
    console.error('\n❌  No se pudo conectar a MySQL:', err.message);
    console.error('    Verifica las credenciales en dbConfig o las variables de entorno.\n');
    process.exit(1);
  }
  connection.release();
  console.log('✅  Conexión a MySQL establecida correctamente.');
  app.listen(PORT, () => {
    console.log(`🏦  Falsoniac Bank escuchando en http://localhost:${PORT}`);
    console.log(`⚠   Aplicación VULNERABLE — solo uso académico\n`);
  });
});
