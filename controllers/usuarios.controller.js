import { readFile, writeFile } from 'fs/promises';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'; // 👈 NUEVO: Para generar el token
import 'dotenv/config';         // 👈 NUEVO: Para leer el JWT_SECRET

const archivoUsuarios = './data/usuarios.json';

/* ------------------------------------------------------------
   Helpers internos
   ------------------------------------------------------------ */
const leerUsuarios = async () => {
  const data = await readFile(archivoUsuarios, 'utf-8');
  return JSON.parse(data);
};

const guardarUsuarios = async (usuarios) => {
  await writeFile(archivoUsuarios, JSON.stringify(usuarios, null, 2));
};

/* Campos obligatorios para crear un usuario */
const CAMPOS_REQUERIDOS = [
  'nombre',
  'edad',
  'ocupacion',
  'ciudad_natal',
  'direccion',
  'email',
  'pass'
];

/* ------------------------------------------------------------
   LOGIN  →  POST /usuarios/login   (ACTUALIZADO CON JWT)
   ------------------------------------------------------------ */
export const login = async (req, res) => {
  try {
    const listaUsuarios = await leerUsuarios();
    const { email, pass } = req.body;

    const usuarioEncontrado = listaUsuarios.find(u => u.email === email);

    if (!usuarioEncontrado) {
      console.log(`❌ Login fallido (email no existe): ${email}`);
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const passValida = await bcrypt.compare(pass, usuarioEncontrado.pass);

    if (!passValida) {
      console.log(`❌ Login fallido (pass incorrecta): ${email}`);
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    /* 🔥 NUEVO: Generamos el Token JWT */
    const payload = { 
      id: usuarioEncontrado.id, 
      email: usuarioEncontrado.email 
    };
    
    // El token vence en 2 horas
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h' });

    /* ========================================================
       LOGS EN CONSOLA DEL BACKEND PARA LA CLASE
       ======================================================== */
    const decoded = jwt.decode(token);
    const fechaVencimiento = new Date(decoded.exp * 1000);

    console.log('\n=========================================');
    console.log('🔑 ¡TOKEN GENERADO CON ÉXITO!');
    console.log(`👤 Usuario: ${usuarioEncontrado.email}`);
    console.log(`🎫 Token: ${token}`);
    console.log(`📦 Payload (datos):`, payload);
    console.log(`⏳ Emitido el: ${new Date().toLocaleString()}`);
    console.log(`🚫 Vence el: ${fechaVencimiento.toLocaleString()}`);
    console.log('=========================================\n');
    /* ======================================================== */

    res.status(200).json({
      mensaje: `Autenticación exitosa, bienvenido ${usuarioEncontrado.nombre}!`,
      token: token // 👈 Le devolvemos el token al front
    });
  } catch (error) {
    console.error('💥 Error en login:', error.message);
    res.status(500).json({ error: 'Error al autenticar el usuario💥.' });
  }
};

/* ------------------------------------------------------------
   LISTAR TODOS  →  GET /usuarios
   ------------------------------------------------------------ */
export const listarUsuarios = async (req, res) => {
  try {
    const listaUsuarios = await leerUsuarios();
    const usuariosSinPass = listaUsuarios.map(({ pass, ...resto }) => resto);
    res.status(200).json(usuariosSinPass);
  } catch (error) {
    console.error('💥 Error al listar:', error.message);
    res.status(500).json({ error: 'Error al listar usuarios💥.' });
  }
};

/* ------------------------------------------------------------
   OBTENER UNO  →  GET /usuarios/:id
   ------------------------------------------------------------ */
export const obtenerUsuario = async (req, res) => {
  try {
    const id = Number(req.params.id);
    const listaUsuarios = await leerUsuarios();
    const usuario = listaUsuarios.find(u => u.id === id);

    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const { pass, ...usuarioSinPass } = usuario;
    res.status(200).json(usuarioSinPass);
  } catch (error) {
    console.error('💥 Error al obtener usuario:', error.message);
    res.status(500).json({ error: 'Error al obtener el usuario💥.' });
  }
};

/* ------------------------------------------------------------
   CREAR  →  POST /usuarios
   ------------------------------------------------------------ */
export const crearUsuario = async (req, res) => {
  try {
    const { nombre, edad, ocupacion, ciudad_natal, direccion, email, pass } = req.body;

    const faltantes = CAMPOS_REQUERIDOS.filter(
      campo => req.body[campo] === undefined || req.body[campo] === ''
    );

    if (faltantes.length > 0) {
      return res.status(400).json({
        error: `Faltan campos obligatorios: ${faltantes.join(', ')}`
      });
    }

    if (typeof edad !== 'number' || edad < 0 || edad > 120) {
      return res.status(400).json({ error: 'La edad debe ser un número entre 0 y 120' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'El email no tiene formato válido' });
    }

    if (pass.length < 8) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
    }

    const listaUsuarios = await leerUsuarios();
    if (listaUsuarios.some(u => u.email === email)) {
      return res.status(409).json({ error: 'El email ya está registrado' });
    }

    const nuevoId = listaUsuarios.length
      ? Math.max(...listaUsuarios.map(u => u.id)) + 1
      : 1;

    const passHasheada = await bcrypt.hash(pass, 10);

    const nuevoUsuario = {
      id: nuevoId, nombre, edad, ocupacion, ciudad_natal, direccion, email, pass: passHasheada
    };

    listaUsuarios.push(nuevoUsuario);
    await guardarUsuarios(listaUsuarios);

    console.log(`✅ Usuario creado: ${email} (id ${nuevoId})`);

    const { pass: _, ...usuarioSinPass } = nuevoUsuario;
    res.status(201).json(usuarioSinPass);
  } catch (error) {
    console.error('💥 Error al crear usuario:', error.message);
    res.status(500).json({ error: 'Error al crear el usuario💥.' });
  }
};

/* ------------------------------------------------------------
   ACTUALIZAR  →  PUT /usuarios/:id
   ------------------------------------------------------------ */
export const actualizarUsuario = async (req, res) => {
  try {
    const id = Number(req.params.id);
    const listaUsuarios = await leerUsuarios();
    const indice = listaUsuarios.findIndex(u => u.id === id);

    if (indice === -1) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const camposEditables = ['nombre', 'edad', 'ocupacion', 'ciudad_natal', 'direccion', 'email', 'pass'];
    const actualizado = { ...listaUsuarios[indice] };

    for (const campo of camposEditables) {
      if (req.body[campo] !== undefined) {
        actualizado[campo] = req.body[campo];
      }
    }

    if (actualizado.edad !== undefined && (typeof actualizado.edad !== 'number' || actualizado.edad < 0 || actualizado.edad > 120)) {
      return res.status(400).json({ error: 'La edad debe ser un número entre 0 y 120' });
    }

    if (req.body.pass) {
      if (req.body.pass.length < 8) {
        return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
      }
      actualizado.pass = await bcrypt.hash(req.body.pass, 10);
    }

    listaUsuarios[indice] = actualizado;
    await guardarUsuarios(listaUsuarios);

    console.log(`✅ Usuario actualizado: id ${id}`);
    const { pass: _, ...usuarioSinPass } = actualizado;
    res.status(200).json(usuarioSinPass);
  } catch (error) {
    console.error('💥 Error al actualizar usuario:', error.message);
    res.status(500).json({ error: 'Error al actualizar el usuario💥.' });
  }
};

/* ------------------------------------------------------------
   ELIMINAR  →  DELETE /usuarios/:id
   ------------------------------------------------------------ */
export const eliminarUsuario = async (req, res) => {
  try {
    const id = Number(req.params.id);
    const listaUsuarios = await leerUsuarios();
    const indice = listaUsuarios.findIndex(u => u.id === id);

    if (indice === -1) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const [eliminado] = listaUsuarios.splice(indice, 1);
    await guardarUsuarios(listaUsuarios);

    console.log(`✅ Usuario eliminado: ${eliminado.email}`);
    res.status(200).json({ mensaje: `Usuario ${eliminado.email} eliminado` });
  } catch (error) {
    console.error('💥 Error al eliminar usuario:', error.message);
    res.status(500).json({ error: 'Error al eliminar el usuario💥.' });
  }
};