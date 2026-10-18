import { MongoClient } from 'mongodb'
import express from "express"
import cors from "cors"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import rateLimit from "express-rate-limit"
import swaggerUi from "swagger-ui-express"
import swaggerDocument from "./openapi.json" with { type: "json" }

const PUERTO = process.env.PORT || 3000
const URL_BD = process.env.MONGODB_URI
const NOMBRE_BD = process.env.DB_NAME || 'api'
const SECRET_KEY = process.env.JWT_SECRET       // Firma el access token
const REFRESH_KEY = process.env.REFRESH_SECRET  // Firma el refresh token

if (!URL_BD || !SECRET_KEY || !REFRESH_KEY) {
    console.error('Faltan variables de entorno: MONGODB_URI, JWT_SECRET y/o REFRESH_SECRET')
    process.exit(1)
}

const app = express()
app.set('trust proxy', 1)
app.use(express.json())
app.use(cors())

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    message: { message: 'Demasiadas peticiones, inténtalo más tarde' }
})
app.use(limiter)

const cliente = new MongoClient(URL_BD, { serverSelectionTimeoutMS: 5000 })
try {
    await cliente.connect()
} catch (err) {
    console.error('No se pudo conectar con MongoDB:', err.message)
    process.exit(1)
}

const bd = cliente.db(NOMBRE_BD)
const usuarios = bd.collection('users')
const motores = bd.collection('motores')
const SIN_PASSWORD = { projection: { password: 0 } } // La contraseña nunca se devuelve

if (await usuarios.countDocuments() === 0) {
    await usuarios.insertMany([
        { id: 0, nombre: "Alex", edad: 30, password: "$2b$10$DJaR.zEOJhgU2CA32EMaL.zImAjxfYPL7NCD9UG.dXdLOciuhzyXS" }, // password: 123456
        { id: 1, nombre: "Ana", edad: 25, password: "$2b$10$l/.WxXkTG6pKVB7KYU/KROXVvH7nAQqyrsq5PW1b.1X4v6L2u00u2" }, // password: ana
        { id: 2, nombre: "Eva", edad: 28, password: "$2b$10$TW/qH6MQ/fd4sRijnHIdoekydhtIonurDMvxZHgqNaIR4st2A90Xe" }  // password: eva
    ])
}

if (await motores.countDocuments() === 0) {
    await motores.insertMany([
        { id: 0, marca: "BMW", modelo: "Serie 3", cilindrada: 2000, combustible: "Diesel", kilometros: 150000, precio: 12000 },
        { id: 1, marca: "Audi", modelo: "A4", cilindrada: 1900, combustible: "Gasolina", kilometros: 120000, precio: 10000 }
    ])
}

function verifyToken(request, response, next) {
    const cabecera = request.headers.authorization || ''
    const [esquema, token] = cabecera.split(' ')

    if (esquema !== 'Bearer' || !token)
        return response.status(401).json({ message: 'Token no proporcionado' })

    try {
        request.user = jwt.verify(token, SECRET_KEY)
        next()
    } catch {
        return response.status(401).json({ message: 'Token no válido o caducado' })
    }
}

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

app.get("/", (request, response) => response.redirect("/api-docs"))

// LOGIN PRINCIPAL
app.post('/api/login', async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const { nombre, password } = request.body

    if (!nombre || !password)
        return response.status(400).json({ message: 'nombre y password son obligatorios' })

    const user = await usuarios.findOne({ nombre })

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return response.status(401).json({ message: "Credenciales incorrectas" })
    }

    const accessToken = jwt.sign(
        { id: user._id, nombre: user.nombre },
        SECRET_KEY,
        { expiresIn: '15m' }
    )

    const refreshToken = jwt.sign(
        { id: user._id, nombre: user.nombre },
        REFRESH_KEY,
        { expiresIn: '7d' }
    )

    response.json({ accessToken, refreshToken })
})

// REFRESH TOKEN
app.post('/api/refresh', async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const { refreshToken } = request.body
    if (!refreshToken) return response.status(401).json({ message: "Refresh token requerido" })

    try {
        const user = jwt.verify(refreshToken, REFRESH_KEY)
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

// -------------- Usuarios ------------------

app.get('/api/users', async (request, response) => {
    const lista = await usuarios.find({}, SIN_PASSWORD).toArray()
    response.json(lista)
})

app.get('/api/users/:id', async (request, response) => {
    const id = Number(request.params.id)
    if (!Number.isInteger(id))
        return response.status(400).json({ message: 'Id no válido' })

    const user = await usuarios.findOne({ id }, SIN_PASSWORD)
    if (user) {
        return response.json(user)
    } else {
        return response.status(404).json({ message: 'El elemento no ha sido encontrado' })
    }
})

app.post('/api/users', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const { nombre, edad, password } = request.body

    if (!nombre || !password)
        return response.status(400).json({ message: 'nombre y password son obligatorios' })

    if (await usuarios.findOne({ nombre }))
        return response.status(409).json({ message: 'Ese usuario ya existe' })

    const ultimo = await usuarios.find().sort({ id: -1 }).limit(1).toArray()
    const id = ultimo.length ? ultimo[0].id + 1 : 0
    const hashedPassword = await bcrypt.hash(password, 10)

    await usuarios.insertOne({ id, nombre, edad, password: hashedPassword })
    const lista = await usuarios.find({}, SIN_PASSWORD).toArray()
    return response.json(lista)
})

app.put('/api/users/:id', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const id = Number(request.params.id)
    if (!Number.isInteger(id))
        return response.status(400).json({ message: 'Id no válido' })

    const { nombre, edad } = request.body
    const resultado = await usuarios.updateOne(
        { id },
        { $set: { nombre, edad } }
    )

    if (resultado.matchedCount > 0) {
        const lista = await usuarios.find({}, SIN_PASSWORD).toArray()
        return response.json(lista)
    } else {
        return response.status(404).json({ message: 'El elemento no ha sido encontrado' })
    }
})

app.delete('/api/users/:id', verifyToken, async (request, response) => {
    const id = Number(request.params.id)
    if (!Number.isInteger(id))
        return response.status(400).json({ message: 'Id no válido' })

    const resultado = await usuarios.deleteOne({ id })

    if (resultado.deletedCount > 0) {
        const lista = await usuarios.find({}, SIN_PASSWORD).toArray()
        return response.json(lista)
    } else {
        return response.status(404).json({ message: 'El elemento no ha sido encontrado' })
    }
})

// -------------- MOTORES ------------------

app.get('/api/motores', async (request, response) => {
    const lista = await motores.find({}).toArray()
    response.json(lista)
})

app.get('/api/motores/:id', async (request, response) => {
    const id = Number(request.params.id)
    if (!Number.isInteger(id))
        return response.status(400).json({ message: 'Id no válido' })

    const motor = await motores.findOne({ id })
    if (motor) {
        return response.json(motor)
    } else {
        return response.status(404).json({ message: 'El elemento no ha sido encontrado' })
    }
})

app.post('/api/motores', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const { marca, modelo, cilindrada, combustible, kilometros, precio } = request.body

    const ultimo = await motores.find().sort({ id: -1 }).limit(1).toArray()
    const id = ultimo.length ? ultimo[0].id + 1 : 0

    await motores.insertOne({ id, marca, modelo, cilindrada, combustible, kilometros, precio })
    const lista = await motores.find({}).toArray()
    return response.json(lista)
})

app.put('/api/motores/:id', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const id = Number(request.params.id)
    if (!Number.isInteger(id))
        return response.status(400).json({ message: 'Id no válido' })

    const { marca, modelo, cilindrada, combustible, kilometros, precio } = request.body
    const resultado = await motores.updateOne(
        { id },
        { $set: { marca, modelo, cilindrada, combustible, kilometros, precio } }
    )

    if (resultado.matchedCount > 0) {
        const lista = await motores.find({}).toArray()
        return response.json(lista)
    } else {
        return response.status(404).json({ message: 'El elemento no ha sido encontrado' })
    }
})

app.delete('/api/motores/:id', verifyToken, async (request, response) => {
    const id = Number(request.params.id)
    if (!Number.isInteger(id))
        return response.status(400).json({ message: 'Id no válido' })

    const resultado = await motores.deleteOne({ id })

    if (resultado.deletedCount > 0) {
        const lista = await motores.find({}).toArray()
        return response.json(lista)
    } else {
        return response.status(404).json({ message: 'El elemento no ha sido encontrado' })
    }
})

// En Vercel no se escucha en un puerto: se exporta la app
if (!process.env.VERCEL) {
    app.listen(PUERTO, () => {
        console.log(`Servidor web iniciado en puerto: ${PUERTO}`)
    })
}

export default app