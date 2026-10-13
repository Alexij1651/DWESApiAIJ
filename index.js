import { MongoClient, ObjectId } from 'mongodb'
import express from "express"
import cors from "cors"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import rateLimit from "express-rate-limit"
import swaggerUi from "swagger-ui-express"
import { createHash, randomUUID } from "node:crypto"
import { swaggerSpec } from "./swagger.js"

const PORT = process.env.PORT ?? 3001
const DB_URL = process.env.MONGODB_URI ?? 'mongodb://localhost:27017'
const DB_NAME = process.env.DB_NAME ?? 'api'
const JWT_SECRET = process.env.JWT_SECRET
const REFRESH_SECRET = process.env.REFRESH_SECRET
const ACCESS_EXPIRES = process.env.ACCESS_EXPIRES ?? '15m'
const REFRESH_EXPIRES_DAYS = 7

const USERS = 'users'
const PRODUCTS = 'products'
const REFRESH_TOKENS = 'refresh_tokens'

if (!JWT_SECRET || !REFRESH_SECRET) {
    console.error('Faltan las variables de entorno JWT_SECRET y/o REFRESH_SECRET')
    process.exit(1)
}

const app = express()
app.set('trust proxy', 1)   
app.use(express.json())     
app.use(cors())             

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Demasiadas peticiones, inténtalo más tarde' }
})

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Demasiados intentos de autenticación, inténtalo más tarde' }
})

app.use(globalLimiter)

const client = new MongoClient(DB_URL)
await client.connect()
const db = client.db(DB_NAME)
const users = db.collection(USERS)
const products = db.collection(PRODUCTS)
const refreshTokens = db.collection(REFRESH_TOKENS)

await users.createIndex({ email: 1 }, { unique: true, partialFilterExpression: { email: { $type: 'string' } } })
await refreshTokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 })

const asyncHandler = (fn) => (request, response, next) =>
    Promise.resolve(fn(request, response, next)).catch(next)

const isValidId = (id) => ObjectId.isValid(id) && String(new ObjectId(id)) === id

const hashToken = (token) => createHash('sha256').update(token).digest('hex')

const isNonEmptyString = (v) => typeof v === 'string' && v.trim().length > 0
const isEmail = (v) => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)

const requireJson = (request, response, next) => {
    if (!request.is('json'))
        return response.status(415).json({ message: 'Debes proporcionar datos JSON' })
    next()
}

const requireValidId = (request, response, next) => {
    if (!isValidId(request.params.id))
        return response.status(400).json({ message: 'Id no válido' })
    next()
}

const signAccessToken = (user) =>
    jwt.sign({ sub: String(user._id), email: user.email }, JWT_SECRET, { expiresIn: ACCESS_EXPIRES })

const issueRefreshToken = async (user) => {
    const token = jwt.sign({ sub: String(user._id) }, REFRESH_SECRET, {
        expiresIn: `${REFRESH_EXPIRES_DAYS}d`,
        jwtid: randomUUID()
    })
    await refreshTokens.insertOne({
        tokenHash: hashToken(token),
        userId: user._id,
        expiresAt: new Date(Date.now() + REFRESH_EXPIRES_DAYS * 24 * 60 * 60 * 1000)
    })
    return token
}

const verifyToken = (request, response, next) => {
    const header = request.headers.authorization ?? ''
    const [scheme, token] = header.split(' ')

    if (scheme !== 'Bearer' || !token)
        return response.status(401).json({ message: 'Token no proporcionado' })

    try {
        request.user = jwt.verify(token, JWT_SECRET)
        next()
    } catch {
        return response.status(401).json({ message: 'Token no válido o caducado' })
    }
}

const validateUserFields = ({ nombre, edad }) => {
    if (!isNonEmptyString(nombre)) return 'El campo "nombre" es obligatorio'
    if (!Number.isInteger(edad) || edad < 0) return 'El campo "edad" debe ser un número entero positivo'
    return null
}

const validateProductFields = ({ nombre, precio }) => {
    if (!isNonEmptyString(nombre)) return 'El campo "nombre" es obligatorio'
    if (typeof precio !== 'number' || !Number.isFinite(precio) || precio < 0)
        return 'El campo "precio" debe ser un número positivo'
    return null
}

const validateCredentials = ({ email, password }) => {
    if (!isEmail(email)) return 'El campo "email" no es válido'
    if (typeof password !== 'string' || password.length < 6)
        return 'La contraseña debe tener al menos 6 caracteres'
    return null
}

const createUser = async ({ nombre, edad, email, password }) => {
    const passwordHash = await bcrypt.hash(password, 10)
    const doc = { nombre: nombre.trim(), edad, email: email.toLowerCase(), passwordHash }
    const result = await users.insertOne(doc)
    return { _id: result.insertedId, nombre: doc.nombre, edad: doc.edad, email: doc.email }
}

const handleDuplicate = (error, response) => {
    if (error?.code === 11000)
        return response.status(409).json({ message: 'Ya existe un usuario con ese email' })
    throw error
}

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec))

app.get("/", (request, response) => {
    response.redirect("/api-docs")
})

app.post('/api/auth/register', authLimiter, requireJson, asyncHandler(async (request, response) => {
    const error = validateUserFields(request.body) ?? validateCredentials(request.body)
    if (error) return response.status(400).json({ message: error })

    try {
        const user = await createUser(request.body)
        return response.status(201).json(user)
    } catch (e) {
        return handleDuplicate(e, response)
    }
}))

app.post('/api/auth/login', authLimiter, requireJson, asyncHandler(async (request, response) => {
    const { email, password } = request.body
    if (!isEmail(email) || typeof password !== 'string')
        return response.status(400).json({ message: 'Email y contraseña son obligatorios' })

    const user = await users.findOne({ email: email.toLowerCase() })
    const valid = user?.passwordHash && await bcrypt.compare(password, user.passwordHash)
    if (!valid) return response.status(401).json({ message: 'Credenciales incorrectas' })

    const accessToken = signAccessToken(user)
    const refreshToken = await issueRefreshToken(user)
    return response.status(200).json({ accessToken, refreshToken })
}))

app.post('/api/auth/refresh', authLimiter, requireJson, asyncHandler(async (request, response) => {
    const { refreshToken } = request.body
    if (!isNonEmptyString(refreshToken))
        return response.status(400).json({ message: 'Falta el refreshToken' })

    let payload
    try {
        payload = jwt.verify(refreshToken, REFRESH_SECRET)
    } catch {
        return response.status(401).json({ message: 'Refresh token no válido o caducado' })
    }

    const stored = await refreshTokens.findOneAndDelete({ tokenHash: hashToken(refreshToken) })
    if (!stored) return response.status(401).json({ message: 'Refresh token revocado' })

    const user = await users.findOne({ _id: new ObjectId(payload.sub) })
    if (!user) return response.status(401).json({ message: 'Usuario no encontrado' })

    const accessToken = signAccessToken(user)
    const newRefreshToken = await issueRefreshToken(user)
    return response.status(200).json({ accessToken, refreshToken: newRefreshToken })
}))

app.post('/api/auth/logout', requireJson, asyncHandler(async (request, response) => {
    const { refreshToken } = request.body
    if (!isNonEmptyString(refreshToken))
        return response.status(400).json({ message: 'Falta el refreshToken' })

    await refreshTokens.deleteOne({ tokenHash: hashToken(refreshToken) })
    return response.status(200).json({ message: 'Sesión cerrada' })
}))

const NO_PASSWORD = { projection: { passwordHash: 0 } }

app.get('/api/users', asyncHandler(async (request, response) => {
    const results = await users.find({}, NO_PASSWORD).toArray()
    response.status(200).json(results)
}))

app.get('/api/users/:id', requireValidId, asyncHandler(async (request, response) => {
    const user = await users.findOne({ _id: new ObjectId(request.params.id) }, NO_PASSWORD)
    if (!user) return response.status(404).json({ message: 'Usuario no encontrado' })
    response.status(200).json(user)
}))

app.post('/api/users', verifyToken, requireJson, asyncHandler(async (request, response) => {
    const error = validateUserFields(request.body) ?? validateCredentials(request.body)
    if (error) return response.status(400).json({ message: error })

    try {
        const user = await createUser(request.body)
        return response.status(201).json(user)
    } catch (e) {
        return handleDuplicate(e, response)
    }
}))

app.put('/api/users/:id', verifyToken, requireJson, requireValidId, asyncHandler(async (request, response) => {
    const error = validateUserFields(request.body)
    if (error) return response.status(400).json({ message: error })

    const { nombre, edad } = request.body
    const result = await users.updateOne(
        { _id: new ObjectId(request.params.id) },
        { $set: { nombre: nombre.trim(), edad } }
    )
    if (result.matchedCount === 0) return response.status(404).json({ message: 'Usuario no encontrado' })
    response.status(200).json(result)
}))

app.delete('/api/users/:id', verifyToken, requireValidId, asyncHandler(async (request, response) => {
    const result = await users.deleteOne({ _id: new ObjectId(request.params.id) })
    if (result.deletedCount === 0) return response.status(404).json({ message: 'Usuario no encontrado' })
    response.status(200).json(result)
}))


app.get('/api/products', asyncHandler(async (request, response) => {
    const results = await products.find({}).toArray()
    response.status(200).json(results)
}))

app.get('/api/products/:id', requireValidId, asyncHandler(async (request, response) => {
    const product = await products.findOne({ _id: new ObjectId(request.params.id) })
    if (!product) return response.status(404).json({ message: 'Producto no encontrado' })
    response.status(200).json(product)
}))

app.post('/api/products', verifyToken, requireJson, asyncHandler(async (request, response) => {
    const error = validateProductFields(request.body)
    if (error) return response.status(400).json({ message: error })

    const { nombre, precio } = request.body
    const doc = { nombre: nombre.trim(), precio }
    const result = await products.insertOne(doc)
    return response.status(201).json({ _id: result.insertedId, ...doc })
}))

app.put('/api/products/:id', verifyToken, requireJson, requireValidId, asyncHandler(async (request, response) => {
    const error = validateProductFields(request.body)
    if (error) return response.status(400).json({ message: error })

    const { nombre, precio } = request.body
    const result = await products.updateOne(
        { _id: new ObjectId(request.params.id) },
        { $set: { nombre: nombre.trim(), precio } }
    )
    if (result.matchedCount === 0) return response.status(404).json({ message: 'Producto no encontrado' })
    response.status(200).json(result)
}))

app.delete('/api/products/:id', verifyToken, requireValidId, asyncHandler(async (request, response) => {
    const result = await products.deleteOne({ _id: new ObjectId(request.params.id) })
    if (result.deletedCount === 0) return response.status(404).json({ message: 'Producto no encontrado' })
    response.status(200).json(result)
}))

app.use((request, response) => {
    response.status(404).json({ message: 'Ruta no encontrada' })
})

app.use((error, request, response, next) => {
    // JSON mal formado
    if (error.type === 'entity.parse.failed')
        return response.status(400).json({ message: 'JSON mal formado' })

    console.error(error)
    response.status(500).json({ message: 'Error interno del servidor' })
})

if (!process.env.VERCEL)
    app.listen(PORT, () => console.log(`Servidor web iniciado en puerto: ${PORT}`))

export default app