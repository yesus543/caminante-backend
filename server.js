const express = require('express');
const mysql = require('mysql');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const BD = mysql.createConnection({
  host: 'srv1960.hstgr.io',
  user: 'u543028883_user_caminante',
  password: 'Cam1nante2024!',
  database: 'u543028883_caminante_db',
});

BD.connect((err) => {
  if (err) {
    console.error('❌ Error de conexión:', err);
  } else {
    console.log('✅ Conectado a MySQL en Hostinger');
  }
});


app.get('/api/productos', (req, res) => {
  BD.query('SELECT * FROM productos', (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error al consultar productos' });
    res.json(result);
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ mensaje: 'Faltan datos' });

  const sql = 'SELECT * FROM usuarios WHERE correo = ? AND contrasena = ?';
  BD.query(sql, [email, password], (err, result) => {
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

  if (!email || !password) return res.status(400).json({ mensaje: 'Todos los campos son obligatorios' });

  BD.query('INSERT INTO usuarios (correo, contrasena) VALUES (?, ?)', [email, password], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ mensaje: 'Correo ya registrado' });
      return res.status(500).json({ mensaje: 'Error interno del servidor' });
    }

    res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor iniciado en puerto ${PORT}`);
});
