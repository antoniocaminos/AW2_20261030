import { readFile, writeFile } from 'fs/promises';
import bcrypt from 'bcryptjs';

const migrarPasswords = async () => {
  try {
    const data = await readFile('./data/usuarios.json', 'utf-8');
    const usuarios = JSON.parse(data);
    
    let modificados = 0;
    
    for (const usuario of usuarios) {
      // Si la pass no empieza con el formato de bcrypt, está en texto plano
      if (usuario.pass && !usuario.pass.startsWith('$2')) {//$2 es el formato de bcryptjs
        usuario.pass = await bcrypt.hash(usuario.pass, 10);//usuario.pass es la contraseña en texto plano. 10 es el número de rondas de salting (puedes ajustarlo según tus necesidades)
        modificados++;
      }
    }
    
    if (modificados > 0) {
      await writeFile('./data/usuarios.json', JSON.stringify(usuarios, null, 2));
      console.log(`✅ Migración exitosa: ${modificados} contraseñas hasheadas.`);
    } else {
      console.log(`✅ Todo en orden: no hay contraseñas en texto plano.`);
    }
  } catch (error) {
    console.error('❌ Error en la migración:', error.message);
  }
};

migrarPasswords();