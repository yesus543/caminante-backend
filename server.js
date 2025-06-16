// server.js

// 1) Carga variables de entorno SIN IMPORTAR NODE_ENV
require('dotenv').config();

const express = require('express');
const mysql   = require('mysql');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3000;

// 2) Validar JWT_SECRET y vars de BD
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET no está definido.');
  process.exit(1);
}

const required = ['DB_HOST','DB_USER','DB_PASSWORD','DB_NAME','JWT_SECRET'];
required.forEach(key => {
  if (!process.env[key]) {
    console.error(`FATAL ERROR: Falta la variable de entorno ${key}`);
    process.exit(1);
  }
});

// 3) Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
}));
app.use(express.json());

// 4) Pool MySQL
const BD = mysql.createPool({
  connectionLimit: 10,
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// 5) Verificar conexión
BD.getConnection((err, conn) => {
  if (err) {
    console.error('❌ Error al conectar con MySQL:', err);
    process.exit(1);
  }
  console.log('✅ Conectado a MySQL');
  conn.release();
});

// 6) Middleware JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ mensaje: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ mensaje: 'Token inválido' });
    req.usuario = decoded; // { id, rol }
    next();
  });
}

// --- tus rutas de registro y login aquí ---

// 7) Obtener usuarios (solo admin)
app.get('/api/usuarios', verifyToken, (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }
  BD.query(
    'SELECT id, correo, rol FROM usuarios',
    (err, results) => {
      if (err) {
        console.error('▶️ Error en GET /api/usuarios:', err);
        return res.status(500).json({
          mensaje: 'Error al obtener usuarios',
          detalle: err.message
        });
      }
      res.json(results);
    }
  );
});




// 11) Modificar contraseña
app.put('/api/usuarios/:id/modificar-password', verifyToken, (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ mensaje: 'Falta la nueva contraseña' });
  }
  if (req.usuario.id !== Number(id) && req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ mensaje: 'Error al hashear contraseña' });
    BD.query('UPDATE usuarios SET contrasena = ? WHERE id = ?', [hash, id], (err) => {
      if (err) return res.status(500).json({ mensaje: 'Error al actualizar contraseña' });
      res.json({ mensaje: 'Contraseña actualizada correctamente' });
    });
  });
});

// 12) Modificar rol
app.put('/api/usuarios/:id/modificar-rol', verifyToken, (req, res) => {
  const { id } = req.params;
  const { rol } = req.body;
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }
  if (!['admin', 'usuario'].includes(rol)) {
    return res.status(400).json({ mensaje: 'Rol inválido' });
  }
  BD.query('UPDATE usuarios SET rol = ? WHERE id = ?', [rol, id], (err) => {
    if (err) return res.status(500).json({ mensaje: 'Error al actualizar rol' });
    res.json({ mensaje: 'Rol actualizado correctamente' });
  });
});

// 13) Eliminar usuario
app.delete('/api/usuarios/:id/eliminar', verifyToken, (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }
  const { id } = req.params;
  BD.query('DELETE FROM usuarios WHERE id = ?', [id], (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error al eliminar usuario' });
    if (result.affectedRows === 0) {
      return res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }
    res.json({ mensaje: 'Usuario eliminado correctamente' });
  });
});

// 14) Obtener rutas
app.get('/api/rutas', verifyToken, (req, res) => {
  const sql = 'SELECT id, destino, precio, horarios, mapa FROM rutas';
  BD.query(sql, (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });
    const rutas = results.map(r => ({
      ...r,
      horarios: typeof r.horarios === 'string' ? JSON.parse(r.horarios) : r.horarios
    }));
    res.json(rutas);
  });
});

// 15) Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor iniciado en puerto ${PORT}`);
});
