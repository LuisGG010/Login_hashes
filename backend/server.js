const express = require('express');
const cookieParser = require('cookie-parser');
const csrf = require('csrf');
const dotenv = require('dotenv');
const crypto = require('crypto');
const cors = require('cors');
const bcrypt = require('bcrypt');


dotenv.config();

const port = process.env.port || 3000; //puerto en el que se va a ejecutar el servidor
const SECRET_KEY = process.env.SECRET_KEY || 'secret'; //clave secreta para el token
//Array de usuarios registrados
const users = [];

// Función para validar el nombre de usuario
function validarUsuario(username) {
    const regexUsuario = /^[a-zA-Z][0-9a-zA-Z]{5,49}$/; // Regex proporcionado
    return regexUsuario.test(username);
};

// Función para validar la contraseña
function validarPassword(password) {
    if (password.length < 10) return false;
    if (!/[A-Z]/.test(password)) return false;
    if (!/[a-z]/.test(password)) return false;
    if (!/[0-9]/.test(password)) return false;
    if (!/[^A-Za-z0-9]/.test(password)) return false;
    return true;
};


const sessions = {};
const secureCookieOptions = () => ({ //opciones de la cookie que se va a crear con los atributos
    httpOnly: true, //solo se puede acceder a la cookie por http
    secure: true, //solo se puede acceder a la cookie por httpS
    sameSite: 'strict' //solo se puede acceder a la cookie desde el mismo sitio
});

const app=express(); //framework basico, recibiendo peticiones y respuestas
app.use(cookieParser()); //toma header cookie y lo convierte en las respectivas variables
app.use(express.json()); //revisa el content type y verifica que estructura tiene todo el documento. Si es json lo convierte en un json
app.use(express.urlencoded({extended: true})); //Los formularios usan x-www-form-urlencoded y esto los descifra con ese formato
app.use(cors({
    origin: 'http://localhost:3001',
    credentials: true
})); //permite que se puedan hacer peticiones desde otros dominios

app.get('/', (req,res) =>{ //cuando se hace una peticion get a la raiz, se ejecuta la funcion
    res.send('Hello World!!'); //devuelve un mensaje
});
app.get('/csrf-token', (req,res) =>{ 
    const csrfToken = new csrf().create(SECRET_KEY); //crea un token con la clave secreta
    res.json({csrfToken}); //devuelve el token (es igual a {'csrfToken': csrfToken})
});

app.post('/login', async (req, res) => {
    const { username, password, csrfToken } = req.body; // Recibe los datos del formulario body
    if (!csrf().verify(SECRET_KEY, csrfToken)) { // Verifica que el token sea válido
        return res.status(400).json({ error: 'CSRF token is invalid' });
    }
    if (!username || !password) { // Si no hay usuario o contraseña, devuelve error 400
        return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    const hashUsuario = crypto.createHash('sha1').update(username.toLowerCase()).digest('hex'); // Genera el hash del nombre de usuario
    const user = users.find(user => user.username === hashUsuario); // Busca el usuario en el array de usuarios

    if (!user || !(await bcrypt.compare(password, user.password))) { // Verifica si el usuario existe y si la contraseña es correcta
        return res.status(400).json({ error: 'Usuario o contraseña incorrectos' });
    }

    const sessionId = crypto.randomBytes(16).toString('base64url'); // Crea un ID de sesión aleatorio
    sessions[sessionId] = { username }; // Guarda el usuario en la sesión
    res.cookie('sessionId', sessionId, secureCookieOptions()); // Crea una cookie con el ID de sesión
    res.status(200).json({ message: 'Login exitoso' }); // Devuelve mensaje de éxito
});

app.post('/register', async (req, res) => { // Cambiar a POST para registrar usuarios
    let { username, password1, password2 } = req.body; // Cambié const a let para permitir modificaciones
    if (!username || !password1 || !password2) { // Si no hay usuario o contraseñas, devuelve error 400
        return res.status(400).json({ error: 'Usuario y contraseñas son requeridos' });
    }
    if (password1 !== password2) { // Si las contraseñas no son iguales, devuelve error 400
        return res.status(400).json({ error: 'Las contraseñas no coinciden' });
    }
    if (!validarUsuario(username)) {
        return res.status(400).json({ error: 'El nombre de usuario no cumple con los requisitos' });
    }
    if (!validarPassword(password1)) {
        return res.status(400).json({ error: 'La contraseña no cumple con los requisitos' });
    }

    const hashUsuario = crypto.createHash('sha1').update(username.toLowerCase()).digest('hex'); // Genera el hash del nombre de usuario
    const usuarioExiste = users.find(user => user.username === hashUsuario); // Busca el usuario en el array de usuarios
    if (usuarioExiste) { // Si el usuario ya existe, devuelve error 409
        return res.status(409).json({ error: 'El usuario es invalido' });
    }
    const hashPassword = await bcrypt.hash(password1, 12); // Hashea la contraseña con bcrypt

    // Guarda el usuario y contraseña hasheados en la base de datos (aquí solo se simula con un array)
    users.push({ username: hashUsuario, password: hashPassword }); // Agrega el nuevo usuario al array de usuarios
    console.log(users); // Muestra el array de usuarios en la consola para verificar que se ha agregado correctamente
    res.status(200).json({ message: 'Usuario registrado exitosamente' }); // Devuelve mensaje de éxito
});

app.listen(port, () =>{
    console.log(`Server listening at http://localhost:${port}`) //muestra en consola el puerto en el que esta corriendo el servidor
});
// ejecutar con node server.js
// ejecutar nodemon con npx nodemon server.js, trabajar con nodemon solo para desarrollo y no para produccion porque es mas pesado y lento







