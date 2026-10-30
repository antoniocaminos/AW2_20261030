import { Router } from 'express';
import {
  login, 
  listarUsuarios, 
  obtenerUsuario, 
  crearUsuario, 
  actualizarUsuario, 
  eliminarUsuario} from '../controllers/usuarios.controller.js';

import { verificarToken } from '../middlewares/auth.middleware.js'; // 👈 NUEVO

const router = Router();

/* Ruta pública: cualquiera puede intentar loguearse */
router.post('/login', login);

/* CRUD */
/* Dejamos el GET público para que todos puedan ver la lista (opcional) */
router.get('/',        listarUsuarios);
router.get('/:id',     obtenerUsuario);

/* 🔥 RUTAS PROTEGIDAS: pasan por el guardián primero */
router.post('/',       verificarToken, crearUsuario);
router.put('/:id',     verificarToken, actualizarUsuario);
router.delete('/:id',  verificarToken, eliminarUsuario);

export default router;