const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Asegúrate de importar bcrypt

const app = express();
const PORT = process.env.PORT || 3000;

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

// Ruta de login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ mensaje: 'Faltan datos' });

  BD.query('SELECT * FROM usuarios WHERE correo = ?', [email], (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });

    if (result.length > 0) {
      const usuario = result[0];
      
      // Comparar las contraseñas usando bcrypt
      bcrypt.compare(password, usuario.contrasena, (err, isMatch) => {
        if (err) return res.status(500).json({ mensaje: 'Error al comparar contraseñas' });

        if (isMatch) {
          const rol = usuario.rol;
          // Si las credenciales son correctas, regresamos los datos del usuario y su rol
          res.json({ autenticado: true, usuario: usuario, rol: rol });
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
  const { email, password } = req.body; // Solo necesitamos correo y contraseña

  if (!email || !password) return res.status(400).json({ mensaje: 'Faltan datos' });

  // Verificar si el correo ya está registrado
  BD.query('SELECT * FROM usuarios WHERE correo = ?', [email], (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error al verificar el correo' });

    if (result.length > 0) {
      return res.status(409).json({ mensaje: 'Correo ya registrado' });
    }

    // Hashear la contraseña antes de guardarla
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ mensaje: 'Error al procesar la contraseña' });

      // Guardar el nuevo usuario con rol 'usuario'
      const query = 'INSERT INTO usuarios (correo, contrasena, rol) VALUES (?, ?, ?)';
      BD.query(query, [email, hashedPassword, 'usuario'], (err) => {
        if (err) return res.status(500).json({ mensaje: 'Error al registrar el usuario' });

        res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
      });
    });
  });
});

// Ruta de registro solo para administradores
app.post('/api/registroAdmin', (req, res) => {
  const { email, password } = req.body; // Solo necesitamos correo y contraseña

  if (!email || !password) return res.status(400).json({ mensaje: 'Faltan datos' });

  // Verificar si el correo ya está registrado
  BD.query('SELECT * FROM usuarios WHERE correo = ?', [email], (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error al verificar el correo' });

    if (result.length > 0) {
      return res.status(409).json({ mensaje: 'Correo ya registrado' });
    }

    // Hashear la contraseña antes de guardarla
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ mensaje: 'Error al procesar la contraseña' });

      // Guardar el nuevo administrador con rol 'admin'
      const query = 'INSERT INTO usuarios (correo, contrasena, rol) VALUES (?, ?, ?)';
      BD.query(query, [email, hashedPassword, 'admin'], (err) => {
        if (err) return res.status(500).json({ mensaje: 'Error al registrar el administrador' });

        res.status(201).json({ mensaje: 'Administrador registrado correctamente' });
      });
    });
  });
});

// Ruta para obtener las rutas disponibles
app.get('/api/rutas', (req, res) => {
  // Consulta a la base de datos para obtener las rutas
  BD.query('SELECT * FROM rutas', (err, result) => {
    if (err) {
      console.error('Error al obtener las rutas:', err);
      return res.status(500).json({ mensaje: 'Error al obtener las rutas' });
    }

    // Formatear los horarios como un arreglo
    const rutas = result.map(ruta => ({
      ...ruta,
      horarios: JSON.parse(ruta.horarios), // Convertir el campo JSON de horarios a un arreglo
    }));

    res.json(rutas); // Devolver las rutas como respuesta
  });
});

// Manejo de errores no capturados
process.on('uncaughtException', (err) => {
  console.error('❌ Error no capturado:', err);
});

process.on('unhandledRejection', (err) => {
  console.error('❌ Promesa rechazada sin capturar:', err);
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor iniciado en puerto ${PORT} :D`);
});
