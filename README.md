# Falsoniac Bank Vulnerable Web App

Aplicación web vulnerable de entrenamiento para Falsoniac Bank. Está diseñada para practicar ataques de seguridad como:

- DDoS (sin límites de tasa y rutas de cálculo intensivo)
- SQL Injection (consultas construidas con concatenación insegura)
- MITM (sitio servido en HTTP simple y cookies inseguras)
- IDOR (acceso a cuentas/transacciones sin validación de dueño)
- SSRF (fetch abierto a cualquier URL)

## Archivos

- `server.js` - backend Express.js vulnerable
- `public/` - frontend HTML estático
- `package.json` - dependencias y script de inicio
- `bank.db` - base de datos SQLite creada en el primer arranque

## Ejecutar

1. Instalar dependencias:

```bash
npm install
```

2. Iniciar la aplicación:

```bash
npm start
```

3. Abrir `http://localhost:3000` en el navegador.

