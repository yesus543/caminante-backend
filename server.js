require('dotenv').config();                // Carga .env
const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Habilitar CORS
app.use(cors({
  origin: 'http://localhost:5173',        // Ajusta según tu frontend
}));

// Parseo de JSON
app.use(express.json());

// Pool de conexiones MySQL
const BD = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Verificación de conexión
BD.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Error al conectar con MySQL:', err);
  } else {
    console.log('✅ Conectado a MySQL');
    connection.release();
  }
});

// Middleware para validar JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) 
    return res.status(401).json({ mensaje: 'Token requerido' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) 
      return res.status(403).json({ mensaje: 'Token inválido' });
    req.usuario = decoded; // { id, rol }
    next();
  });
}

// Ruta de login: genera JWT
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) 
    return res.status(400).json({ mensaje: 'Faltan datos' });

  BD.query('SELECT * FROM usuarios WHERE correo = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });
    if (results.length === 0) 
      return res.status(401).json({ autenticado: false, mensaje: 'Correo no encontrado' });

    const usuario = results[0];
    bcrypt.compare(password, usuario.contrasena, (err, isMatch) => {
      if (err) return res.status(500).json({ mensaje: 'Error al comparar contraseñas' });
      if (!isMatch) 
        return res.status(401).json({ autenticado: false, mensaje: 'Contraseña incorrecta' });

      // 1. Construir payload
      const payload = { id: usuario.id, rol: usuario.rol };
      // 2. Firmar JWT
      const token = jwt.sign(
        payload,
        process.env.JWT_SECRET,   // Debe estar en tu .env
        { expiresIn: '1h' }
      );

      // 3. Enviar token al cliente
      res.json({
        autenticado: true,
        usuario: { id: usuario.id, correo: usuario.correo, rol: usuario.rol },
        token
      });
    });
  });
});

// Ruta para obtener todos los usuarios (solo admin)
app.get('/api/usuarios', verifyToken, (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }

  BD.query('SELECT id, nombre, correo, rol FROM usuarios', (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error al obtener usuarios' });
    res.json(results);
  });
});

// Ruta para modificar contraseña
app.put('/api/usuarios/:id/modificar-password', verifyToken, (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  if (!password) return res.status(400).json({ mensaje: 'Falta la nueva contraseña' });

  // Solo el propio usuario o admin
  if (req.usuario.id !== Number(id) && req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ mensaje: 'Error al hashear contraseña' });
    BD.query(
      'UPDATE usuarios SET contrasena = ? WHERE id = ?',
      [hash, id],
      (err) => {
        if (err) return res.status(500).json({ mensaje: 'Error al actualizar contraseña' });
        res.json({ mensaje: 'Contraseña actualizada correctamente' });
      }
    );
  });
});

// Ruta para modificar rol (solo admin)
app.put('/api/usuarios/:id/modificar-rol', verifyToken, (req, res) => {
  const { id } = req.params;
  const { rol } = req.body;
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado' });
  }
  if (!rol || (rol !== 'admin' && rol !== 'usuario')) {
    return res.status(400).json({ mensaje: 'Rol inválido' });
  }

  BD.query(
    'UPDATE usuarios SET rol = ? WHERE id = ?',
    [rol, id],
    (err) => {
      if (err) return res.status(500).json({ mensaje: 'Error al actualizar rol' });
      res.json({ mensaje: 'Rol actualizado correctamente' });
    }
  );
});
// Justo antes de app.listen(...)
app.get('/api/rutas', verifyToken, (req, res) => {
  const sql = 'SELECT id, destino, precio, horarios, mapa FROM rutas';
  BD.query(sql, (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });
    // Parsear JSON si tus horarios vienen como texto
    const rutas = results.map(r => ({
      ...r,
      horarios: typeof r.horarios === 'string'
        ? JSON.parse(r.horarios)
        : r.horarios
    }));
    res.json(rutas);
  });
});

// Ruta para eliminar un usuario (solo admin)
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

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor iniciado en puerto ${PORT}`);
});
