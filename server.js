const express = require('express');
const mysql = require('mysql');
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const BD = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'NavarroG240102', // Cambia por tu contraseña real
  database: 'caminante',
});

BD.connect((err) => {
  if (err) throw err;
  console.log('Conexión exitosa a MySQL');
});

// Ruta GET de prueba
app.get('/api/productos', (req, res) => {
  const SQL_QUERY = 'SELECT * FROM productos';
  BD.query(SQL_QUERY, (err, result) => {
    if (err) throw err;
    res.json(result);
  });
});

// Ruta POST para login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ mensaje: 'Faltan datos' });
  }

  const SQL_QUERY = 'SELECT * FROM usuarios WHERE correo = ? AND contrasena = ?';
  BD.query(SQL_QUERY, [email, password], (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error interno' });

    if (result.length > 0) {
      res.json({ autenticado: true, usuario: result[0] });
    } else {
      res.status(401).json({ autenticado: false, mensaje: 'Credenciales incorrectas' });
    }
  });
});

app.post('/api/registro', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ mensaje: 'Todos los campos son obligatorios' });
  }

  const sql = 'INSERT INTO usuarios (correo, contrasena) VALUES (?, ?)';

  BD.query(sql, [email, password], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ mensaje: 'Correo ya registrado' });
      }
      return res.status(500).json({ mensaje: 'Error interno del servidor' });
    }

    res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
  });
});


// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
