import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs"  // Hashing de contraseñas
import jwt from "jsonwebtoken" // Generacion y verificacion de tokens
import swaggerUi from "swagger-ui-express"
import swaggerDocument from "./openapi.json" with { type: "json" }
// Para que swagger funcione correctamente en Vercel es necesario archivo vercel.json
// y añadir configuración indicada en https://github.com/swagger-api/swagger-ui/issues/9924#issuecomment-3360835086


const SECRET_KEY = "secreto" // Secreto para firmar y verificar el token
const app = express()

//Estas contraseñas son las que nos permite iniciar sesion
let Users = [
    { id: 0, nombre: "Alex", edad: 30, password: "$2b$10$DJaR.zEOJhgU2CA32EMaL.zImAjxfYPL7NCD9UG.dXdLOciuhzyXS" }, // password: 123456
    { id: 1, nombre: "Ana", edad: 25, password: "$2b$10$l/.WxXkTG6pKVB7KYU/KROXVvH7nAQqyrsq5PW1b.1X4v6L2u00u2" }, // password: ana
    { id: 2, nombre: "Eva", edad: 28, password: "$2b$10$TW/qH6MQ/fd4sRijnHIdoekydhtIonurDMvxZHgqNaIR4st2A90Xe" }  // password: eva
]

let Motores = [
    { id: 0, marca: "BMW", modelo: "Serie 3", cilindrada: 2000, combustible: "Diesel", kilometros: 150000, precio: 12000 },
    { id: 1, marca: "Audi", modelo: "A4", cilindrada: 1900, combustible: "Gasolina", kilometros: 120000, precio: 10000 }
]



app.use(express.json())   // IMPORTANTE
app.use(cors())           // Para habilitar CORS
app.use(
    "/api-docs",
    swaggerUi.serve,
    swaggerUi.setup(swaggerDocument)
)



function verifyToken(request, response, next) {
    const token = request.headers.authorization?.split(" ")[1]; // formato "Bearer <token>"

    if (!token) return response.status(403).json({ message: "Token requerido" });

    try {
        request.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (err) {
        return response.status(403).json({ message: "Token inválido" });
    }
}


// Redirigir a la documentación de la API
app.get("/", (request, response) => response.redirect("/api-docs"))


// LOGIN
app.post('/api/login', async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const { nombre, password } = request.body

    const user = Users.find(u => u.nombre == nombre)

    if (user == undefined) {
        return response.status(401).json({ message: "Usuario no encontrado" })
    }

    // Comparamos la contraseña
    const correctPassword = await bcrypt.compare(password, user.password)

    if (!correctPassword) {
        return response.status(401).json({ message: "Contraseña incorrecta" })
    }

    // Generamos el Access Token (corta duración, ej: 15 minutos)
    const accessToken = jwt.sign(
        { id: user.id, nombre: user.nombre },
        SECRET_KEY,
        { expiresIn: '15m' }
    )

    // Generamos el Refresh Token (larga duración, ej: 7 días)
    const refreshToken = jwt.sign(
        { id: user.id, nombre: user.nombre },
        SECRET_KEY,
        { expiresIn: '7d' }
    )

    response.json({ accessToken, refreshToken })
})

// REFRESH TOKEN
app.post('/api/refresh', (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const { refreshToken } = request.body

    if (!refreshToken) {
        return response.status(401).json({ message: "Refresh token requerido" })
    }

    try {
        // Verificamos el refresh token
        const user = jwt.verify(refreshToken, SECRET_KEY)

        // Generamos un nuevo access token
        const accessToken = jwt.sign(
            { id: user.id, nombre: user.nombre },
            SECRET_KEY,
            { expiresIn: '15m' }
        )

        response.json({ accessToken })
    } catch (err) {
        return response.status(401).json({ message: "Refresh token inválido o expirado" })
    }
})


// -------------- USERS ------------------

// GET
app.get('/api/users', (request, response) => response.json(Users))

// GET 
app.get('/api/users/:id', (request, response) => {
    let user = Users.find(u => u.id == request.params.id)

    if (user !== undefined) { // Si es encontrado    
        return response.json(user)
    } else {
        response.json({ message: 'El elemento no ha sido encontrado' })
    }
})


// POST 
app.post('/api/users', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    let sig = Users.length > 0 ? Math.max(...Users.map(u => u.id)) + 1 : 0

    const { nombre, edad, password } = request.body
    const hashedPassword = await bcrypt.hash(password, 10)
    Users.push({ id: sig, nombre, edad, password: hashedPassword })
    return response.json(Users)
})


// PUT
app.put('/api/users/:id', verifyToken, (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const { id } = request.params
    const { nombre, edad } = request.body

    // Obtenemos posición    
    const pos = Users.findIndex(u => u.id == id)

    if (pos != -1) { // Si es encontrado
        const password = Users[pos].password
        Users.splice(pos, 1, { id: Number(id), nombre, edad, password })
        return response.json(Users)
    } else { // Sino
        response.json({ message: 'El elemento no ha sido encontrado' })
    }
})

// DELETE
app.delete('/api/users/:id', verifyToken, (request, response) => {
    // Obtenemos posición    
    const pos = Users.findIndex(u => u.id == request.params.id)

    if (pos != -1) { // Si es encontrado
        Users.splice(pos, 1)
        return response.json(Users)
    } else { // Sino
        response.json({ message: 'El elemento no ha sido encontrado' })
    }
})


// -------------- MOTORES (desguace) ------------------

// GET
app.get('/api/motores', (request, response) => response.json(Motores))

// GET 
app.get('/api/motores/:id', (request, response) => {
    let motor = Motores.find(m => m.id == request.params.id)

    if (motor !== undefined) { // Si es encontrado    
        return response.json(motor)
    } else {
        response.json({ message: 'El elemento no ha sido encontrado' })
    }
})


// POST 
app.post('/api/motores', verifyToken, (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    let sig = Motores.length > 0 ? Math.max(...Motores.map(m => m.id)) + 1 : 0

    const { marca, modelo, cilindrada, combustible, kilometros, precio } = request.body
    Motores.push({ id: sig, marca, modelo, cilindrada, combustible, kilometros, precio })
    return response.json(Motores)
})


// PUT
app.put('/api/motores/:id', verifyToken, (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const { id } = request.params
    const { marca, modelo, cilindrada, combustible, kilometros, precio } = request.body

    // Obtenemos posición    
    const pos = Motores.findIndex(m => m.id == id)

    if (pos != -1) { // Si es encontrado
        Motores.splice(pos, 1, { id: Number(id), marca, modelo, cilindrada, combustible, kilometros, precio })
        return response.json(Motores)
    } else { // Sino
        response.json({ message: 'El elemento no ha sido encontrado' })
    }
})

// DELETE
app.delete('/api/motores/:id', verifyToken, (request, response) => {
    // Obtenemos posición    
    const pos = Motores.findIndex(m => m.id == request.params.id)

    if (pos != -1) { // Si es encontrado
        Motores.splice(pos, 1)
        return response.json(Motores)
    } else { // Sino
        response.json({ message: 'El elemento no ha sido encontrado' })
    }
})

const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
    console.log(`Servidor web iniciado en puerto: 3001`)
    console.log(`Documentación de Swagger disponible en: http://localhost:3001/api-docs`)
})

export default app