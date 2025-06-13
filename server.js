const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Asegúrate de importar bcrypt

const app = express();
const PORT = process.env.PORT || 3000;

// Habilitar CORS para permitir solicitudes desde el frontend
app.use(cors({
  origin: 'http://localhost:5173', // Si tu frontend está en localhost con Vite
  // origin: 'https://mi-frontend.com', // Si tu frontend está en producción
}));

// Middleware para parsear el body como JSON
app.use(express.json());

// Conexión a la base de datos
const BD = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,  // Ejemplo: 'mi-servidor.mysql.hostinger.com'
  user: process.env.DB_USER,  // Tu usuario MySQL
  password: process.env.DB_PASSWORD,  // Tu contraseña MySQL
  database: process.env.DB_NAME,  // El nombre de tu base de datos
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

// Ruta de registro (solo para usuarios)
app.post('/api/registroUSER', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ mensaje: 'Faltan datos' });

  BD.query('SELECT * FROM usuarios WHERE correo = ?', [email], (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error al verificar el correo' });

    if (result.length > 0) {
      return res.status(409).json({ mensaje: 'Correo ya registrado' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ mensaje: 'Error al procesar la contraseña' });

      const query = 'INSERT INTO usuarios (correo, contrasena, rol) VALUES (?, ?, ?)';
      BD.query(query, [email, hashedPassword, 'usuario'], (err) => {
        if (err) return res.status(500).json({ mensaje: 'Error al registrar el usuario' });

        res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
      });
    });
  });
});

// Ruta para modificar la contraseña de un usuario
app.put('/api/usuarios/:id/modificar-password', (req, res) => {
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
app.put('/api/usuarios/:id/modificar-rol', (req, res) => {
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
app.get('/api/usuarios', (req, res) => {
  const query = 'SELECT * FROM usuarios';
  BD.query(query, (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error al obtener los usuarios' });
    res.json(result);
  });
});

// Ruta para eliminar un usuario
app.delete('/api/usuarios/:id/eliminar', (req, res) => {
  const { id } = req.params;

  // Verificar el token de autenticación
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).json({ mensaje: 'No se proporcionó un token de autenticación' });
  }

  // Decodificar y verificar el token JWT
  jwt.verify(token, 'tu_clave_secreta', (err, decoded) => {
    if (err) {
      return res.status(403).json({ mensaje: 'Token inválido' });
    }

    // Verificar si el usuario tiene rol de admin
    const usuario = decoded;  // Suponiendo que el rol y otros datos del usuario estén decodificados en el token
    if (usuario.rol !== 'admin') {
      return res.status(403).json({ mensaje: 'No tienes permisos para eliminar usuarios' });
    }

    const query = 'DELETE FROM usuarios WHERE id = ?';
    BD.query(query, [id], (err, result) => {
      if (err) {
        return res.status(500).json({ mensaje: 'Error al eliminar el usuario' });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ mensaje: 'Usuario no encontrado' });
      }

      res.json({ mensaje: 'Usuario eliminado correctamente' });
    });
  });
});



// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor iniciado en puerto ${PORT}`);
});
