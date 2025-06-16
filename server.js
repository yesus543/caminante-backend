// server.js (corregido)

// 1) Carga variables de entorno siempre
require('dotenv').config();

const express = require('express');
const mysql   = require('mysql');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3000;

// 2) Validar vars de entorno
const required = ['JWT_SECRET','DB_HOST','DB_USER','DB_PASSWORD','DB_NAME'];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`FATAL ERROR: La variable de entorno ${key} no está definida.`);
    process.exit(1);
  }
}
const JWT_SECRET = process.env.JWT_SECRET;

// 3) Middlewares
app.use(cors({ origin: process.env.CORS_ORIGIN || 'http://localhost:5173' }));
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
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ mensaje: 'Token requerido' });
  const token = auth.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ mensaje: 'Token inválido' });
    req.usuario = decoded;
    next();
  });
}

// 7) Registro de usuario (público)
app.post('/api/registroUSER', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ mensaje: 'Faltan datos' });
  }
  // Validar existencia
  BD.query('SELECT id FROM usuarios WHERE correo = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });
    if (results.length > 0) {
      return res.status(409).json({ mensaje: 'Correo ya registrado' });
    }
    // Hashear y registrar como usuario
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.status(500).json({ mensaje: 'Error al procesar contraseña' });
      BD.query(
        'INSERT INTO usuarios (correo, contrasena, rol) VALUES (?, ?, ?)',
        [email, hash, 'usuario'],
        err => {
          if (err) return res.status(500).json({ mensaje: 'Error al registrar usuario' });
          res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
        }
      );
    });
  });
});

// 8) Registro de administrador (solo admin)
app.post('/api/registroAdmin', verifyToken, (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado: solo administradores' });
  }
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ mensaje: 'Faltan datos' });
  }
  BD.query('SELECT id FROM usuarios WHERE correo = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });
    if (results.length > 0) {
      return res.status(409).json({ mensaje: 'Correo ya registrado' });
    }
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.status(500).json({ mensaje: 'Error al procesar contraseña' });
      BD.query(
        'INSERT INTO usuarios (correo, contrasena, rol) VALUES (?, ?, ?)',
        [email, hash, 'admin'],
        err => {
          if (err) return res.status(500).json({ mensaje: 'Error al registrar administrador' });
          res.status(201).json({ mensaje: 'Administrador registrado correctamente' });
        }
      );
    });
  });
});

// 9) Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ mensaje: 'Faltan datos' });
  }
  BD.query('SELECT * FROM usuarios WHERE correo = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });
    if (results.length === 0) {
      return res.status(401).json({ autenticado: false, mensaje: 'Correo no encontrado' });
    }
    const usuario = results[0];
    bcrypt.compare(password, usuario.contrasena, (err, match) => {
      if (err) return res.status(500).json({ mensaje: 'Error al comparar contraseñas' });
      if (!match) return res.status(401).json({ autenticado: false, mensaje: 'Contraseña incorrecta' });
      const token = jwt.sign({ id: usuario.id, rol: usuario.rol }, JWT_SECRET, { expiresIn: '1h' });
      res.json({ autenticado: true, usuario: { id: usuario.id, correo: usuario.correo, rol: usuario.rol }, token });
    });
  });
});

// 10) Obtener usuarios (solo admin)
app.get('/api/usuarios', verifyToken, (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }
  BD.query('SELECT id, correo, rol FROM usuarios', (err, results) => {
    if (err) {
      console.error('▶️ Error en GET /api/usuarios:', err);
      return res.status(500).json({ mensaje: 'Error al obtener usuarios', detalle: err.message });
    }
    res.json(results);
  });
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


// 11) Agregar nueva ruta (solo admin)
app.post('/api/agregarRuta', verifyToken, (req, res) => {
  // Sólo administradores
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado: solo administradores' });
  }

  const {
    destino,
    precio,
    horarios,
    direccion,
    telefono,
    horarioSucursal,
    mapa
  } = req.body;

  // Validar obligatorios
  if (!destino || precio == null || !horarios || !direccion) {
    return res.status(400).json({ mensaje: 'Faltan datos obligatorios' });
  }

  // Convertir horarios a array de strings
  const horariosArr = Array.isArray(horarios)
    ? horarios
    : horarios.split(',').map(h => h.trim());

  // Insertar en la tabla 'rutas'
  const sql = `
    INSERT INTO rutas
      (destino, precio, horarios, direccion, telefono, horarioSucursal, mapa)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;
  BD.query(
    sql,
    [
      destino,
      precio,                            // decimal(10,2)
      JSON.stringify(horariosArr),       // longtext
      direccion,                         // varchar(255)
      telefono  || null,                 // varchar(20)
      horarioSucursal || null,           // varchar(50)
      mapa                              // text
    ],
    (err, result) => {
      if (err) {
        console.error('Error al agregar ruta:', err);
        return res.status(500).json({ mensaje: 'Error interno al agregar ruta' });
      }
      res.status(201).json({
        mensaje: 'Ruta agregada correctamente',
        id: result.insertId
      });
    }
  );
});

// 15) Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor iniciado en puerto ${PORT}`);
});
