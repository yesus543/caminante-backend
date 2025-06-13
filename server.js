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

// Ruta para agregar una nueva ruta
app.post('/api/agregarRuta', (req, res) => {
  const { destino, precio, horarios, direccion, telefono, horarioSucursal, mapa } = req.body;

  if (!destino || !precio || !horarios || !direccion || !telefono || !horarioSucursal || !mapa) {
    return res.status(400).json({ mensaje: 'Faltan datos en el formulario' });
  }

  // Insertar la nueva ruta en la base de datos
  const query = 'INSERT INTO rutas (destino, precio, horarios, direccion, telefono, horarioSucursal, mapa) VALUES (?, ?, ?, ?, ?, ?, ?)';
  
  BD.query(query, [destino, precio, JSON.stringify(horarios.split(',')), direccion, telefono, horarioSucursal, mapa], (err, result) => {
    if (err) {
      return res.status(500).json({ mensaje: 'Error al agregar la ruta' });
    }

    res.status(201).json({ mensaje: 'Ruta agregada con éxito' });
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

// Ruta para modificar la contraseña de un usuario
app.put('/api/usuarios/:id/modificar-password', (req, res) => {
  const { id } = req.params; // ID del usuario que se quiere modificar
  const { password } = req.body; // Nueva contraseña

  if (!password) return res.status(400).json({ mensaje: 'Falta la nueva contraseña' });

  // Hashear la nueva contraseña
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ mensaje: 'Error al procesar la contraseña' });

    // Actualizar la contraseña en la base de datos
    const query = 'UPDATE usuarios SET contrasena = ? WHERE id = ?';
    BD.query(query, [hashedPassword, id], (err, result) => {
      if (err) {
        return res.status(500).json({ mensaje: 'Error al actualizar la contraseña' });
      }

      res.json({ mensaje: 'Contraseña actualizada correctamente' });
    });
  });
});

// Ruta para modificar el rol de un usuario
app.put('/api/usuarios/:id/modificar-rol', (req, res) => {
  const { id } = req.params; // ID del usuario que se quiere modificar
  const { rol } = req.body; // Nuevo rol

  if (!rol) return res.status(400).json({ mensaje: 'Falta el nuevo rol' });

  // Verificar que el rol sea válido
  if (rol !== 'admin' && rol !== 'usuario') {
    return res.status(400).json({ mensaje: 'Rol inválido' });
  }

  // Actualizar el rol en la base de datos
  const query = 'UPDATE usuarios SET rol = ? WHERE id = ?';
  BD.query(query, [rol, id], (err, result) => {
    if (err) {
      return res.status(500).json({ mensaje: 'Error al actualizar el rol' });
    }

    res.json({ mensaje: 'Rol actualizado correctamente' });
  });
});

// Ruta para obtener todos los usuarios (solo para admins)
app.get('/api/usuarios', (req, res) => {
  const usuario = JSON.parse(req.headers['usuario']); // Aquí se asume que el usuario logueado se pasa en los headers
  if (!usuario || usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'No tienes permisos para acceder a esta ruta' });
  }

  // Obtener todos los usuarios
  const query = 'SELECT * FROM usuarios';
  BD.query(query, (err, result) => {
    if (err) {
      console.error('Error al obtener los usuarios:', err);
      return res.status(500).json({ mensaje: 'Error al obtener los usuarios' });
    }

    res.json(result); // Retornar la lista de usuarios
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
