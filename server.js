const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Habilitar CORS
app.use(cors());
app.use(express.json());

// Conexión a la base de datos
const BD = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Verificación de la conexión
BD.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Error al conectar con MySQL:', err);
  } else {
    console.log('✅ Conectado a MySQL en Hostinger');
    connection.release();
  }
});

// Middleware para verificar que el usuario es admin
const verificarAdmin = (req, res, next) => {
  const usuario = JSON.parse(req.headers['usuario']);
  if (!usuario || usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'No tienes permisos para realizar esta acción' });
  }
  next();
};

// Ruta de login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ mensaje: 'Faltan datos' });

  BD.query('SELECT * FROM usuarios WHERE correo = ?', [email], (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });

    if (result.length > 0) {
      const usuario = result[0];
      
      bcrypt.compare(password, usuario.contrasena, (err, isMatch) => {
        if (err) return res.status(500).json({ mensaje: 'Error al comparar contraseñas' });

        if (isMatch) {
          res.json({ autenticado: true, usuario: usuario, rol: usuario.rol });
        } else {
          res.status(401).json({ autenticado: false, mensaje: 'Contraseña incorrecta' });
        }
      });
    } else {
      res.status(401).json({ autenticado: false, mensaje: 'Correo no encontrado' });
    }
  });
});

// Ruta para modificar la contraseña de un usuario
app.put('/api/usuarios/:id/modificar-password', verificarAdmin, (req, res) => {
  const { id } = req.params;
  const { password } = req.body;

  if (!password) return res.status(400).json({ mensaje: 'Falta la nueva contraseña' });

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ mensaje: 'Error al procesar la contraseña' });

    const query = 'UPDATE usuarios SET contrasena = ? WHERE id = ?';
    BD.query(query, [hashedPassword, id], (err, result) => {
      if (err) return res.status(500).json({ mensaje: 'Error al actualizar la contraseña' });
      res.json({ mensaje: 'Contraseña actualizada correctamente' });
    });
  });
});

// Ruta para modificar el rol de un usuario
app.put('/api/usuarios/:id/modificar-rol', verificarAdmin, (req, res) => {
  const { id } = req.params;
  const { rol } = req.body;

  if (!rol || (rol !== 'admin' && rol !== 'usuario')) {
    return res.status(400).json({ mensaje: 'Rol inválido' });
  }

  const query = 'UPDATE usuarios SET rol = ? WHERE id = ?';
  BD.query(query, [rol, id], (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error al actualizar el rol' });
    res.json({ mensaje: 'Rol actualizado correctamente' });
  });
});

// Ruta para obtener los usuarios (solo admin)
app.get('/api/usuarios', verificarAdmin, (req, res) => {
  const query = 'SELECT * FROM usuarios';
  BD.query(query, (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error al obtener los usuarios' });
    res.json(result);
  });
});

app.listen(PORT, () => {
  console.log(`Servidor iniciado en puerto ${PORT}`);
});
