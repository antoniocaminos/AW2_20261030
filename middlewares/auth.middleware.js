import jwt from 'jsonwebtoken';
import 'dotenv/config';

export const verificarToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log(`⛔ Acceso denegado: No hay token en la petición`);
    return res.status(401).json({ error: 'Acceso denegado. Token no proporcionado.' });
  }

  try {
    const verificado = jwt.verify(token, process.env.JWT_SECRET);
    
    // 🔥 LOG EN CONSOLA DEL BACKEND
    console.log(`\n🛡️ Middleware: Token verificado.`);
    console.log(`   Acceso permitido al usuario: ${verificado.email}`);
    
    req.usuario = verificado; 
    next(); // Pasa a la ruta
  } catch (error) {
    console.log(`⛔ Acceso denegado: Token inválido o vencido`);
    return res.status(403).json({ error: 'Token inválido o vencido.' });
  }
};