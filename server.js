const express = require('express');
const mysql = require('mysql');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const BD = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

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

  // Consulta para verificar el usuario y su rol
  BD.query(
    'SELECT * FROM usuarios WHERE correo = ? AND contrasena = ?',
    [email, password],
    (err, result) => {
      if (err) return res.status(500).json({ mensaje: 'Error interno' });

      if (result.length > 0) {
        const usuario = result[0];

        // Verificamos el rol del usuario
        const rol = usuario.rol;

        // Enviamos la respuesta dependiendo del rol
        if (rol === 'admin') {
          res.json({ autenticado: true, usuario: usuario, rol: 'admin' });
        } else if (rol === 'usuario') {
          res.json({ autenticado: true, usuario: usuario, rol: 'usuario' });
        } else {
          res.status(403).json({ autenticado: false, mensaje: 'Rol desconocido' });
        }
      } else {
        res.status(401).json({ autenticado: false, mensaje: 'Credenciales incorrectas' });
      }
    }
  );
});

// Ruta de registro
app.post('/api/registro', (req, res) => {
  const { email, password, rol } = req.body;
  if (!email || !password || !rol) return res.status(400).json({ mensaje: 'Faltan datos' });

  // Validar rol (debe ser 'admin' o 'usuario')
  if (rol !== 'admin' && rol !== 'usuario') {
    return res.status(400).json({ mensaje: 'Rol no válido' });
  }

  BD.query(
    'INSERT INTO usuarios (correo, contrasena, rol) VALUES (?, ?, ?)',
    [email, password, rol],
    (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ mensaje: 'Correo ya registrado' });
        }
        return res.status(500).json({ mensaje: 'Error al registrar' });
      }
      res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
    }
  );
});
app.post('/api/registrar-admin', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ mensaje: 'Email y contraseña son obligatorios' });
  }

  // Hashear la contraseña antes de guardarla
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ mensaje: 'Error al procesar la contraseña' });

    // Guardar el nuevo administrador en la base de datos
    const query = 'INSERT INTO usuarios (correo, contrasena, rol) VALUES (?, ?, ?)';
    BD.query(query, [email, hashedPassword, 'admin'], (err, result) => {
      if (err) return res.status(500).json({ mensaje: 'Error al agregar el administrador' });
      
      res.status(201).json({ mensaje: 'Administrador agregado con éxito' });
    });
  });
});


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
