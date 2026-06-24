# 🏦 Falsoniac Bank — Entorno vulnerable de laboratorio

Aplicación bancaria con vulnerabilidades intencionadas para uso académico en cursos de ciberseguridad.

---

## Requisitos

- Node.js 18+
- MySQL 8.x (o MariaDB 10.6+)

---

## Instalación rápida

### 1. Crear la base de datos en MySQL

```sql
CREATE DATABASE falsoniac_bank CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 2. Importar el schema y datos de prueba

```bash
mysql -u root -p falsoniac_bank < schema.sql
```

### 3. Configurar credenciales de conexión

Edita `server.js` en el bloque `dbConfig` o usa variables de entorno:

```bash
export DB_HOST=localhost
export DB_PORT=3306
export DB_USER=root
export DB_PASSWORD=tu_password
export DB_NAME=falsoniac_bank
```

### 4. Instalar dependencias e iniciar

```bash
npm install
npm start
```

Accede en: **http://localhost:3000**

---

## Cuentas de prueba

| Usuario | Contraseña   | Rol      |
|---------|-------------|----------|
| alice   | password123 | customer |
| bob     | secret456   | customer |
| carlos  | carlos2024  | customer |
| admin   | adminpass   | admin    |

---

## Mapa de vulnerabilidades

| Vulnerabilidad | Endpoint(s)                        | Página            |
|----------------|------------------------------------|-------------------|
| SQL Injection  | `POST /login`, `GET /account`      | login.html        |
| IDOR           | `GET /account?id=X`, `/movements`  | transfer.html, movements.html |
| SSRF           | `GET /api/fetch-rate?source=URL`   | tools.html        |
| DoS            | `GET /api/report?depth=N`          | tools.html        |
| MITM           | Cookie `falsoniac_session`         | todas las páginas |

---

> ⚠ **USO EXCLUSIVO EN ENTORNOS CONTROLADOS DE LABORATORIO**
