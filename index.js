import { MongoClient, ObjectId } from 'mongodb'
import express from "express"
import cors from "cors"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import rateLimit from "express-rate-limit"
import swaggerUi from "swagger-ui-express"
import { createHash, randomUUID } from "node:crypto"
import { swaggerSpec } from "./swagger.js"

const PUERTO = process.env.PORT ?? 3001
const URL_BD = process.env.MONGODB_URI ?? 'mongodb://localhost:27017'
const NOMBRE_BD = process.env.DB_NAME ?? 'api'
const SECRETO_JWT = process.env.JWT_SECRET
const SECRETO_REFRESH = process.env.REFRESH_SECRET
const CADUCIDAD_ACCESO = process.env.ACCESS_EXPIRES ?? '15m'
const DIAS_CADUCIDAD_REFRESH = 7

const USUARIOS = 'users'
const PRODUCTOS = 'products'
const TOKENS_REFRESCO = 'refresh_tokens'

if (!SECRETO_JWT || !SECRETO_REFRESH) {
    console.error('Faltan las variables de entorno JWT_SECRET y/o REFRESH_SECRET')
    process.exit(1)
}

const app = express()
app.set('trust proxy', 1)
app.use(express.json())
app.use(cors())

const limitadorGlobal = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Demasiadas peticiones, inténtalo más tarde' }
})

const limitadorAuth = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Demasiados intentos de autenticación, inténtalo más tarde' }
})

app.use(limitadorGlobal)

const cliente = new MongoClient(URL_BD)
await cliente.connect()
const bd = cliente.db(NOMBRE_BD)
const usuarios = bd.collection(USUARIOS)
const productos = bd.collection(PRODUCTOS)
const tokensRefresco = bd.collection(TOKENS_REFRESCO)

await usuarios.createIndex({ email: 1 }, { unique: true, partialFilterExpression: { email: { $type: 'string' } } })
await tokensRefresco.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 })

const manejadorAsync = (funcion) => (peticion, respuesta, siguiente) =>
    Promise.resolve(funcion(peticion, respuesta, siguiente)).catch(siguiente)

const esIdValido = (id) => ObjectId.isValid(id) && String(new ObjectId(id)) === id

const hashearToken = (token) => createHash('sha256').update(token).digest('hex')

const esTextoNoVacio = (valor) => typeof valor === 'string' && valor.trim().length > 0
const esEmail = (valor) => typeof valor === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(valor)

const exigirJson = (peticion, respuesta, siguiente) => {
    if (!peticion.is('json'))
        return respuesta.status(415).json({ message: 'Debes proporcionar datos JSON' })
    siguiente()
}

const exigirIdValido = (peticion, respuesta, siguiente) => {
    if (!esIdValido(peticion.params.id))
        return respuesta.status(400).json({ message: 'Id no válido' })
    siguiente()
}

const firmarTokenAcceso = (usuario) =>
    jwt.sign({ sub: String(usuario._id), email: usuario.email }, SECRETO_JWT, { expiresIn: CADUCIDAD_ACCESO })

const emitirTokenRefresco = async (usuario) => {
    const token = jwt.sign({ sub: String(usuario._id) }, SECRETO_REFRESH, {
        expiresIn: `${DIAS_CADUCIDAD_REFRESH}d`,
        jwtid: randomUUID()
    })
    await tokensRefresco.insertOne({
        tokenHash: hashearToken(token),
        userId: usuario._id,
        expiresAt: new Date(Date.now() + DIAS_CADUCIDAD_REFRESH * 24 * 60 * 60 * 1000)
    })
    return token
}

const verificarToken = (peticion, respuesta, siguiente) => {
    const cabecera = peticion.headers.authorization ?? ''
    const [esquema, token] = cabecera.split(' ')

    if (esquema !== 'Bearer' || !token)
        return respuesta.status(401).json({ message: 'Token no proporcionado' })

    try {
        peticion.usuario = jwt.verify(token, SECRETO_JWT)
        siguiente()
    } catch {
        return respuesta.status(401).json({ message: 'Token no válido o caducado' })
    }
}

const validarCamposUsuario = ({ nombre, edad }) => {
    if (!esTextoNoVacio(nombre)) return 'El campo "nombre" es obligatorio'
    if (!Number.isInteger(edad) || edad < 0) return 'El campo "edad" debe ser un número entero positivo'
    return null
}

const validarCamposProducto = ({ nombre, precio }) => {
    if (!esTextoNoVacio(nombre)) return 'El campo "nombre" es obligatorio'
    if (typeof precio !== 'number' || !Number.isFinite(precio) || precio < 0)
        return 'El campo "precio" debe ser un número positivo'
    return null
}

const validarCredenciales = ({ email, password }) => {
    if (!esEmail(email)) return 'El campo "email" no es válido'
    if (typeof password !== 'string' || password.length < 6)
        return 'La contraseña debe tener al menos 6 caracteres'
    return null
}

const crearUsuario = async ({ nombre, edad, email, password }) => {
    const passwordHash = await bcrypt.hash(password, 10)
    const documento = { nombre: nombre.trim(), edad, email: email.toLowerCase(), passwordHash }
    const resultado = await usuarios.insertOne(documento)
    return { _id: resultado.insertedId, nombre: documento.nombre, edad: documento.edad, email: documento.email }
}

const manejarDuplicado = (fallo, respuesta) => {
    if (fallo?.code === 11000)
        return respuesta.status(409).json({ message: 'Ya existe un usuario con ese email' })
    throw fallo
}

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec))

app.get("/", (peticion, respuesta) => {
    respuesta.redirect("/api-docs")
})

app.post('/api/auth/register', limitadorAuth, exigirJson, manejadorAsync(async (peticion, respuesta) => {
    const error = validarCamposUsuario(peticion.body) ?? validarCredenciales(peticion.body)
    if (error) return respuesta.status(400).json({ message: error })

    try {
        const usuario = await crearUsuario(peticion.body)
        return respuesta.status(201).json(usuario)
    } catch (fallo) {
        return manejarDuplicado(fallo, respuesta)
    }
}))

app.post('/api/auth/login', limitadorAuth, exigirJson, manejadorAsync(async (peticion, respuesta) => {
    const { email, password } = peticion.body
    if (!esEmail(email) || typeof password !== 'string')
        return respuesta.status(400).json({ message: 'Email y contraseña son obligatorios' })

    const usuario = await usuarios.findOne({ email: email.toLowerCase() })
    const valida = usuario?.passwordHash && await bcrypt.compare(password, usuario.passwordHash)
    if (!valida) return respuesta.status(401).json({ message: 'Credenciales incorrectas' })

    const tokenAcceso = firmarTokenAcceso(usuario)
    const tokenRefresco = await emitirTokenRefresco(usuario)
    return respuesta.status(200).json({ accessToken: tokenAcceso, refreshToken: tokenRefresco })
}))

app.post('/api/auth/refresh', limitadorAuth, exigirJson, manejadorAsync(async (peticion, respuesta) => {
    const { refreshToken: tokenRefresco } = peticion.body
    if (!esTextoNoVacio(tokenRefresco))
        return respuesta.status(400).json({ message: 'Falta el refreshToken' })

    let carga
    try {
        carga = jwt.verify(tokenRefresco, SECRETO_REFRESH)
    } catch {
        return respuesta.status(401).json({ message: 'Refresh token no válido o caducado' })
    }

    const guardado = await tokensRefresco.findOneAndDelete({ tokenHash: hashearToken(tokenRefresco) })
    if (!guardado) return respuesta.status(401).json({ message: 'Refresh token revocado' })

    const usuario = await usuarios.findOne({ _id: new ObjectId(carga.sub) })
    if (!usuario) return respuesta.status(401).json({ message: 'Usuario no encontrado' })

    const tokenAcceso = firmarTokenAcceso(usuario)
    const tokenRefrescoNuevo = await emitirTokenRefresco(usuario)
    return respuesta.status(200).json({ accessToken: tokenAcceso, refreshToken: tokenRefrescoNuevo })
}))

app.post('/api/auth/logout', exigirJson, manejadorAsync(async (peticion, respuesta) => {
    const { refreshToken: tokenRefresco } = peticion.body
    if (!esTextoNoVacio(tokenRefresco))
        return respuesta.status(400).json({ message: 'Falta el refreshToken' })

    await tokensRefresco.deleteOne({ tokenHash: hashearToken(tokenRefresco) })
    return respuesta.status(200).json({ message: 'Sesión cerrada' })
}))

const SIN_PASSWORD = { projection: { passwordHash: 0 } }

app.get('/api/users', manejadorAsync(async (peticion, respuesta) => {
    const resultados = await usuarios.find({}, SIN_PASSWORD).toArray()
    respuesta.status(200).json(resultados)
}))

app.get('/api/users/:id', exigirIdValido, manejadorAsync(async (peticion, respuesta) => {
    const usuario = await usuarios.findOne({ _id: new ObjectId(peticion.params.id) }, SIN_PASSWORD)
    if (!usuario) return respuesta.status(404).json({ message: 'Usuario no encontrado' })
    respuesta.status(200).json(usuario)
}))

app.post('/api/users', verificarToken, exigirJson, manejadorAsync(async (peticion, respuesta) => {
    const error = validarCamposUsuario(peticion.body) ?? validarCredenciales(peticion.body)
    if (error) return respuesta.status(400).json({ message: error })

    try {
        const usuario = await crearUsuario(peticion.body)
        return respuesta.status(201).json(usuario)
    } catch (fallo) {
        return manejarDuplicado(fallo, respuesta)
    }
}))

app.put('/api/users/:id', verificarToken, exigirJson, exigirIdValido, manejadorAsync(async (peticion, respuesta) => {
    const error = validarCamposUsuario(peticion.body)
    if (error) return respuesta.status(400).json({ message: error })

    const { nombre, edad } = peticion.body
    const resultado = await usuarios.updateOne(
        { _id: new ObjectId(peticion.params.id) },
        { $set: { nombre: nombre.trim(), edad } }
    )
    if (resultado.matchedCount === 0) return respuesta.status(404).json({ message: 'Usuario no encontrado' })
    respuesta.status(200).json(resultado)
}))

app.delete('/api/users/:id', verificarToken, exigirIdValido, manejadorAsync(async (peticion, respuesta) => {
    const resultado = await usuarios.deleteOne({ _id: new ObjectId(peticion.params.id) })
    if (resultado.deletedCount === 0) return respuesta.status(404).json({ message: 'Usuario no encontrado' })
    respuesta.status(200).json(resultado)
}))


app.get('/api/products', manejadorAsync(async (peticion, respuesta) => {
    const resultados = await productos.find({}).toArray()
    respuesta.status(200).json(resultados)
}))

app.get('/api/products/:id', exigirIdValido, manejadorAsync(async (peticion, respuesta) => {
    const producto = await productos.findOne({ _id: new ObjectId(peticion.params.id) })
    if (!producto) return respuesta.status(404).json({ message: 'Producto no encontrado' })
    respuesta.status(200).json(producto)
}))

app.post('/api/products', verificarToken, exigirJson, manejadorAsync(async (peticion, respuesta) => {
    const error = validarCamposProducto(peticion.body)
    if (error) return respuesta.status(400).json({ message: error })

    const { nombre, precio } = peticion.body
    const documento = { nombre: nombre.trim(), precio }
    const resultado = await productos.insertOne(documento)
    return respuesta.status(201).json({ _id: resultado.insertedId, ...documento })
}))

app.put('/api/products/:id', verificarToken, exigirJson, exigirIdValido, manejadorAsync(async (peticion, respuesta) => {
    const error = validarCamposProducto(peticion.body)
    if (error) return respuesta.status(400).json({ message: error })

    const { nombre, precio } = peticion.body
    const resultado = await productos.updateOne(
        { _id: new ObjectId(peticion.params.id) },
        { $set: { nombre: nombre.trim(), precio } }
    )
    if (resultado.matchedCount === 0) return respuesta.status(404).json({ message: 'Producto no encontrado' })
    respuesta.status(200).json(resultado)
}))

app.delete('/api/products/:id', verificarToken, exigirIdValido, manejadorAsync(async (peticion, respuesta) => {
    const resultado = await productos.deleteOne({ _id: new ObjectId(peticion.params.id) })
    if (resultado.deletedCount === 0) return respuesta.status(404).json({ message: 'Producto no encontrado' })
    respuesta.status(200).json(resultado)
}))

app.use((peticion, respuesta) => {
    respuesta.status(404).json({ message: 'Ruta no encontrada' })
})

app.use((error, peticion, respuesta, siguiente) => {
    // JSON mal formado
    if (error.type === 'entity.parse.failed')
        return respuesta.status(400).json({ message: 'JSON mal formado' })

    console.error(error)
    respuesta.status(500).json({ message: 'Error interno del servidor' })
})

if (!process.env.VERCEL)
    app.listen(PUERTO, () => console.log(`Servidor web iniciado en puerto: ${PUERTO}`))

export default app