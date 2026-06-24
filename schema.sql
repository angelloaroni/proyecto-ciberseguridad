-- =============================================================================
-- FALSONIAC BANK — Schema MySQL
-- Entorno académico de ciberseguridad — NO usar en producción
-- =============================================================================
-- Uso:
--   1. Crear la base de datos:   CREATE DATABASE falsoniac_bank;
--   2. Ejecutar este archivo:    mysql -u root -p falsoniac_bank < schema.sql
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64)  NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,   -- [VULN] texto plano, sin hash
  role     VARCHAR(32)  NOT NULL DEFAULT 'customer',
  email    VARCHAR(128),
  phone    VARCHAR(32)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS accounts (
  id      INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT          NOT NULL,
  balance DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  label   VARCHAR(128) NOT NULL,
  type    VARCHAR(32)  NOT NULL DEFAULT 'corriente',
  FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS transactions (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  account_id INT            NOT NULL,
  amount     DECIMAL(15,2)  NOT NULL,
  note       VARCHAR(255),
  created_at DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (account_id) REFERENCES accounts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ─── Datos de prueba ─────────────────────────────────────────────────────────

INSERT IGNORE INTO users (username, password, role, email, phone) VALUES
  ('alice',  'password123', 'customer', 'alice@falsoniac.com',  '987-111-001'),
  ('bob',    'secret456',   'customer', 'bob@falsoniac.com',    '987-222-002'),
  ('carlos', 'carlos2024',  'customer', 'carlos@falsoniac.com', '987-333-003'),
  ('admin',  'adminpass',   'admin',    'admin@falsoniac.com',  '987-000-000');

INSERT IGNORE INTO accounts (user_id, balance, label, type) VALUES
  (1,    4520.50,  'Cuenta Corriente',  'corriente'),
  (1,    1280.00,  'Cuenta de Ahorros', 'ahorros'),
  (2,   16200.75,  'Cuenta Corriente',  'corriente'),
  (3,    3050.00,  'Cuenta Corriente',  'corriente'),
  (4,  999999.99,  'Cuenta VIP',        'vip');

INSERT IGNORE INTO transactions (account_id, amount, note) VALUES
  (1,  -120.00, 'Pago de servicio de luz'),
  (1,   500.00, 'Depósito en efectivo'),
  (1,  -250.00, 'Transferencia a Carlos'),
  (2,   300.00, 'Abono de nómina'),
  (3,   540.00, 'Depósito recibido'),
  (3,  -800.00, 'Retiro cajero'),
  (4,  -200.00, 'Pago proveedor'),
  (5, -9999.99, 'Transferencia internacional');
