// server.js

// 1) Carga de variables de entorno en desarrollo
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const mysql   = require('mysql');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3000;

// 2) Configuración de CORS
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  // credentials: true // si envías cookies
}));

// 3) Middleware para parsear JSON
app.use(express.json());

// 4) Conexión a MySQL mediante pool
const BD = mysql.createPool({
  connectionLimit: 10,
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// 5) Verificar conexión a la base de datos
BD.getConnection((err, conn) => {
  if (err) {
    console.error('❌ Error al conectar con MySQL:', err);
  } else {
    console.log('✅ Conectado a MySQL');
    conn.release();
  }
});

// 6) Middleware para validar JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ mensaje: 'Token requerido' });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ mensaje: 'Token inválido' });
    }
    req.usuario = decoded; // contiene { id, rol }
    next();
  });
}

// 7) Autenticación: Login y generación de JWT
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ mensaje: 'Faltan datos' });
  }

  BD.query('SELECT * FROM usuarios WHERE correo = ?', [email], (err, results) => {
    if (err) {
      return res.status(500).json({ mensaje: 'Error interno' });
    }
    if (results.length === 0) {
      return res.status(401).json({ autenticado: false, mensaje: 'Correo no encontrado' });
    }

    const usuario = results[0];
    bcrypt.compare(password, usuario.contrasena, (err, isMatch) => {
      if (err) {
        return res.status(500).json({ mensaje: 'Error al comparar contraseñas' });
      }
      if (!isMatch) {
        return res.status(401).json({ autenticado: false, mensaje: 'Contraseña incorrecta' });
      }

      const payload = { id: usuario.id, rol: usuario.rol };
      const token   = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

      res.json({
        autenticado: true,
        usuario:     { id: usuario.id, correo: usuario.correo, rol: usuario.rol },
        token
      });
    });
  });
});

// 8) Obtener todos los usuarios (solo admin)
app.get('/api/usuarios', verifyToken, (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }
  BD.query('SELECT id, nombre, correo, rol FROM usuarios', (err, results) => {
    if (err) {
      return res.status(500).json({ mensaje: 'Error al obtener usuarios' });
    }
    res.json(results);
  });
});

// 9) Modificar contraseña (propio usuario o admin)
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
    if (err) {
      return res.status(500).json({ mensaje: 'Error al hashear contraseña' });
    }
    BD.query(
      'UPDATE usuarios SET contrasena = ? WHERE id = ?',
      [hash, id],
      (err) => {
        if (err) {
          return res.status(500).json({ mensaje: 'Error al actualizar contraseña' });
        }
        res.json({ mensaje: 'Contraseña actualizada correctamente' });
      }
    );
  });
});

// 10) Modificar rol (solo admin)
app.put('/api/usuarios/:id/modificar-rol', verifyToken, (req, res) => {
  const { id } = req.params;
  const { rol } = req.body;
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }
  if (!['admin', 'usuario'].includes(rol)) {
    return res.status(400).json({ mensaje: 'Rol inválido' });
  }

  BD.query(
    'UPDATE usuarios SET rol = ? WHERE id = ?',
    [rol, id],
    (err) => {
      if (err) {
        return res.status(500).json({ mensaje: 'Error al actualizar rol' });
      }
      res.json({ mensaje: 'Rol actualizado correctamente' });
    }
  );
});

// 11) Eliminar usuario (solo admin)
app.delete('/api/usuarios/:id/eliminar', verifyToken, (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }
  const { id } = req.params;
  BD.query('DELETE FROM usuarios WHERE id = ?', [id], (err, result) => {
    if (err) {
      return res.status(500).json({ mensaje: 'Error al eliminar usuario' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }
    res.json({ mensaje: 'Usuario eliminado correctamente' });
  });
});

// 12) Obtener rutas (usuarios autenticados)
app.get('/api/rutas', verifyToken, (req, res) => {
  const sql = 'SELECT id, destino, precio, horarios, mapa FROM rutas';
  BD.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ mensaje: 'Error interno' });
    }
    const rutas = results.map(r => ({
      ...r,
      horarios: typeof r.horarios === 'string' ? JSON.parse(r.horarios) : r.horarios
    }));
    res.json(rutas);
  });
});

// 13) Arrancar el servidor
app.listen(PORT, () => {
  console.log(`Servidor iniciado en puerto ${PORT}`);
});
