const express = require('express');
const mysql = require('mysql');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ✅ Conexión usando variables de entorno
const BD = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Verificar conexión
BD.connect((err) => {
  if (err) {
    console.error('❌ Error al conectar a MySQL:', err);
    return;
  }
  console.log('✅ Conexión exitosa a MySQL');
});

// Rutas de ejemplo
app.get('/api/productos', (req, res) => {
  BD.query('SELECT * FROM productos', (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error en consulta' });
    res.json(result);
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ mensaje: 'Faltan datos' });

  BD.query('SELECT * FROM usuarios WHERE correo = ? AND contrasena = ?', [email, password], (err, result) => {
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
  if (!email || !password) return res.status(400).json({ mensaje: 'Faltan datos' });

  BD.query('INSERT INTO usuarios (correo, contrasena) VALUES (?, ?)', [email, password], (err) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ mensaje: 'Correo ya registrado' });
      }
      return res.status(500).json({ mensaje: 'Error interno' });
    }
    res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor iniciado en puerto ${PORT}`);
});
