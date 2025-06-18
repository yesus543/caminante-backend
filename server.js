// server.js

// 1) Carga variables de entorno
require('dotenv').config();

const express = require('express');
const mysql   = require('mysql');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3000;

// 2) Validar variables de entorno
const required = [
  'JWT_SECRET',
  'DB_HOST',
  'DB_USER',
  'DB_PASSWORD',
  'DB_NAME',
  'CORS_ORIGIN'
];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`FATAL ERROR: La variable de entorno ${key} no está definida.`);
    process.exit(1);
  }
}
const JWT_SECRET = process.env.JWT_SECRET;

// 3) Configuración dinámica de CORS
const allowedOrigins = [
  process.env.CORS_ORIGIN,       // e.g. http://localhost:5173
  'https://www.caminante.site'   // dominio de producción
];

app.use(cors({
  origin: (origin, callback) => {
    // permitir peticiones sin origin (Postman, mobile apps, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error(`CORS Denied for origin ${origin}`), false);
  },
  credentials: true
}));

// 4) Middleware JSON
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

// 8) Registro de nuevo usuario (incluyendo taquillero y volantero)
app.post('/api/registroUsuario', verifyToken, (req, res) => {
  // Verificamos si el rol del usuario autenticado es admin
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado: solo administradores' });
  }

  const { email, password, rol } = req.body;
  
  // Verificamos que el rol esté permitido
  if (!['taquillero', 'volantero'].includes(rol)) {
    return res.status(400).json({ mensaje: 'Rol inválido. Solo taquillero o volantero son permitidos.' });
  }

  if (!email || !password || !rol) {
    return res.status(400).json({ mensaje: 'Faltan datos' });
  }

  // Verificamos si el correo ya está registrado
  BD.query('SELECT id FROM usuarios WHERE correo = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });
    if (results.length > 0) {
      return res.status(409).json({ mensaje: 'Correo ya registrado' });
    }

    // Hash de la contraseña antes de guardarla
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.status(500).json({ mensaje: 'Error al procesar contraseña' });
      
      // Insertamos el nuevo usuario con el rol seleccionado (taquillero o volantero)
      BD.query(
        'INSERT INTO usuarios (correo, contrasena, rol) VALUES (?, ?, ?)',
        [email, hash, rol],
        err => {
          if (err) return res.status(500).json({ mensaje: 'Error al registrar usuario' });
          res.status(201).json({ mensaje: `Usuario registrado correctamente como ${rol}` });
        }
      );
    });
  });
});


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

      // Generar el token JWT
      const token = jwt.sign({ id: usuario.id, rol: usuario.rol }, JWT_SECRET, { expiresIn: '1h' });

      // Aquí no es necesario cambiar nada si solo necesitas enviar el rol
      res.json({
        autenticado: true,
        usuario: { id: usuario.id, correo: usuario.correo, rol: usuario.rol },
        token,
      });
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
  if (!['admin', 'usuario','taquillero', 'volantero'].includes(rol)) {
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
    if (err) {
      console.error('Error en GET /api/rutas:', err);
      return res.status(500).json({ mensaje: 'Error interno al obtener rutas' });
    }
    const rutas = results.map(r => ({
      id:       r.id,
      destino:  r.destino,
      precio:   r.precio,
      horarios: typeof r.horarios === 'string'
                 ? JSON.parse(r.horarios)
                 : r.horarios,
      mapa:     r.mapa
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

// Modificar ruta (solo admin)
app.put('/api/rutas/:id', verifyToken, (req, res) => {
  // 1) Sólo admins
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acceso denegado: solo administradores' });
  }

  const { id } = req.params;
  const {
    destino,
    precio,
    horarios,
    direccion,
    telefono,
    horarioSucursal,
    mapa
  } = req.body;

  // 2) Validar campos obligatorios
  if (!destino || precio == null || !horarios || !direccion) {
    return res.status(400).json({ mensaje: 'Faltan datos obligatorios' });
  }

  // 3) Asegurarnos de que horarios sea un array
  const horariosArr = Array.isArray(horarios)
    ? horarios
    : horarios.split(',').map(h => h.trim());

  // 4) Ejecutar UPDATE
  const sql = `
    UPDATE rutas
    SET destino = ?, precio = ?, horarios = ?, direccion = ?, telefono = ?, horarioSucursal = ?, mapa = ?
    WHERE id = ?
  `;
  BD.query(
    sql,
    [
      destino,
      precio,
      JSON.stringify(horariosArr),
      direccion,
      telefono  || null,
      horarioSucursal || null,
      mapa || null,
      id
    ],
    (err, result) => {
      if (err) {
        console.error('Error al modificar ruta:', err);
        return res.status(500).json({ mensaje: 'Error interno al modificar ruta' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ mensaje: 'Ruta no encontrada' });
      }
      res.json({ mensaje: 'Ruta actualizada correctamente' });
    }
  );
});
// 1) Obtener asientos de una ruta
app.get('/api/rutas/:id/asientos', verifyToken, (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT fila, columna, ocupado FROM asientos WHERE ruta_id = ?';
  BD.query(sql, [id], (err, results) => {
    if (err) {
      console.error('Error GET /api/rutas/:id/asientos:', err);
      return res.status(500).json({ mensaje: 'Error al obtener asientos' });
    }
    const asientoMap = {};
    results.forEach(({ fila, columna, ocupado }) => {
      asientoMap[`${fila}-${columna}`] = !!ocupado;
    });
    res.json({ asientos: asientoMap });
  });
});

// 2) Reservar asiento (después de pago)
app.post('/api/rutas/:id/reservar', verifyToken, (req, res) => {
  const { id } = req.params;
  const { fila, columna } = req.body;
  const usuarioId = req.usuario.id;

  if (fila == null || columna == null) {
    return res.status(400).json({ mensaje: 'Faltan datos de asiento' });
  }

  // 2.a) verificar existencia y estado
  const checkSql = 'SELECT ocupado FROM asientos WHERE ruta_id = ? AND fila = ? AND columna = ?';
  BD.query(checkSql, [id, fila, columna], (err, rows) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });
    if (rows.length === 0) {
      return res.status(404).json({ mensaje: 'Asiento no existe' });
    }
    if (rows[0].ocupado) {
      return res.status(409).json({ mensaje: 'Asiento ya reservado' });
    }
    // 2.b) marcar como ocupado
    const updateSql = `
      UPDATE asientos
      SET ocupado = 1, usuario_id = ?
      WHERE ruta_id = ? AND fila = ? AND columna = ?
    `;
    BD.query(updateSql, [usuarioId, id, fila, columna], err => {
      if (err) {
        console.error('Error POST /api/rutas/:id/reservar:', err);
        return res.status(500).json({ mensaje: 'Error al reservar asiento' });
      }
      res.json({ mensaje: 'Asiento reservado correctamente', fila, columna });
    });
  });
});
app.get('/api/mis-reservas', verifyToken, (req, res) => {
  const usuarioId = req.usuario.id;
  const sql = `
    SELECT a.ruta_id AS rutaId,
           r.destino,
           a.fila,
           a.columna,
           r.precio
    FROM asientos a
    JOIN rutas r ON a.ruta_id = r.id
    WHERE a.usuario_id = ? AND a.ocupado = 1
  `;
  BD.query(sql, [usuarioId], (err, results) => {
    if (err) {
      console.error('Error GET /api/mis-reservas:', err);
      return res.status(500).json({ mensaje: 'Error al obtener tus reservas' });
    }
    const reservas = results.map(r => ({
      rutaId: r.rutaId,
      destino: r.destino,
      fila: r.fila,
      columna: r.columna,
      precio: r.precio
    }));
    res.json(reservas);
  });
});

// 17) Cancelar reserva (liberar asiento)
app.delete('/api/mis-reservas/:rutaId/:fila/:columna', verifyToken, (req, res) => {
  const usuarioId = req.usuario.id;
  const { rutaId, fila, columna } = req.params;

  // Verificar que la reserva pertenezca al usuario
  const lookup = `
    SELECT ocupado FROM asientos
    WHERE ruta_id = ? AND fila = ? AND columna = ? AND usuario_id = ?
  `;
  BD.query(lookup, [rutaId, fila, columna, usuarioId], (err, rows) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });
    if (rows.length === 0) {
      return res.status(404).json({ mensaje: 'Reserva no encontrada' });
    }
    // Liberar asiento
    const update = `
      UPDATE asientos
      SET ocupado = 0, usuario_id = NULL
      WHERE ruta_id = ? AND fila = ? AND columna = ?
    `;
    BD.query(update, [rutaId, fila, columna], err => {
      if (err) {
        console.error('Error DELETE /api/mis-reservas:', err);
        return res.status(500).json({ mensaje: 'Error al cancelar reserva' });
      }
      res.json({ mensaje: 'Reserva cancelada correctamente' });
    });
  });
});
// 15) Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor iniciado en puerto ${PORT}`);
});
