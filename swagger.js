const bearer = [{ bearerAuth: [] }]

const idParam = {
    name: 'id',
    in: 'path',
    required: true,
    schema: { type: 'string', example: '65f1a2b3c4d5e6f7a8b9c0d1' }
}

const json = (schema) => ({ content: { 'application/json': { schema } } })
const ref = (name) => ({ $ref: `#/components/schemas/${name}` })

const errorResponses = {
    400: { description: 'Datos no válidos', ...json(ref('Error')) },
    401: { description: 'Token no proporcionado, no válido o caducado', ...json(ref('Error')) },
    404: { description: 'No encontrado', ...json(ref('Error')) },
    429: { description: 'Demasiadas peticiones (rate limit)', ...json(ref('Error')) }
}

const pick = (...codes) => Object.fromEntries(codes.map((c) => [c, errorResponses[c]]))

// Genera las rutas CRUD de un recurso
const crud = (tag, path, singular, schema, inputSchema) => ({
    [`/api/${path}`]: {
        get: {
            tags: [tag],
            summary: `Listar ${path}`,
            responses: {
                200: { description: 'Listado', ...json({ type: 'array', items: ref(schema) }) },
                ...pick(429)
            }
        },
        post: {
            tags: [tag],
            summary: `Crear ${singular}`,
            security: bearer,
            requestBody: { required: true, ...json(ref(inputSchema)) },
            responses: {
                201: { description: 'Creado', ...json(ref(schema)) },
                409: { description: 'Ya existe (email duplicado)', ...json(ref('Error')) },
                ...pick(400, 401, 429)
            }
        }
    },
    [`/api/${path}/{id}`]: {
        get: {
            tags: [tag],
            summary: `Obtener ${singular} por id`,
            parameters: [idParam],
            responses: {
                200: { description: 'Encontrado', ...json(ref(schema)) },
                ...pick(400, 404, 429)
            }
        },
        put: {
            tags: [tag],
            summary: `Actualizar ${singular}`,
            security: bearer,
            parameters: [idParam],
            requestBody: {
                required: true,
                ...json(ref(tag === 'Usuarios' ? 'UserUpdate' : 'ProductInput'))
            },
            responses: {
                200: { description: 'Actualizado' },
                ...pick(400, 401, 404, 429)
            }
        },
        delete: {
            tags: [tag],
            summary: `Eliminar ${singular}`,
            security: bearer,
            parameters: [idParam],
            responses: {
                200: { description: 'Eliminado' },
                ...pick(400, 401, 404, 429)
            }
        }
    }
})

export const swaggerSpec = {
    openapi: '3.0.3',
    info: {
        title: 'API REST - Usuarios y Productos',
        version: '1.0.0',
        description:
            'API con MongoDB Atlas. Los GET son públicos; POST, PUT y DELETE requieren un access token JWT ' +
            '(cabecera `Authorization: Bearer <token>`). Incluye rate limit global (100 peticiones / 15 min) ' +
            'y más estricto en /auth (10 / 15 min).'
    },
    servers: [{ url: '/' }],
    tags: [
        { name: 'Auth', description: 'Registro, login y renovación de tokens' },
        { name: 'Usuarios' },
        { name: 'Productos' }
    ],
    components: {
        securitySchemes: {
            bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }
        },
        schemas: {
            Error: {
                type: 'object',
                properties: { message: { type: 'string', example: 'Descripción del error' } }
            },
            User: {
                type: 'object',
                properties: {
                    _id: { type: 'string', example: '65f1a2b3c4d5e6f7a8b9c0d1' },
                    nombre: { type: 'string', example: 'Alex' },
                    edad: { type: 'integer', example: 20 },
                    email: { type: 'string', example: 'alex@correo.com' }
                }
            },
            UserInput: {
                type: 'object',
                required: ['nombre', 'edad', 'email', 'password'],
                properties: {
                    nombre: { type: 'string', example: 'Alex' },
                    edad: { type: 'integer', example: 20 },
                    email: { type: 'string', example: 'alex@correo.com' },
                    password: { type: 'string', minLength: 6, example: '123456' }
                }
            },
            UserUpdate: {
                type: 'object',
                required: ['nombre', 'edad'],
                properties: {
                    nombre: { type: 'string', example: 'Alex' },
                    edad: { type: 'integer', example: 21 }
                }
            },
            Product: {
                type: 'object',
                properties: {
                    _id: { type: 'string', example: '65f1a2b3c4d5e6f7a8b9c0d2' },
                    nombre: { type: 'string', example: 'Teclado' },
                    precio: { type: 'number', example: 29.99 }
                }
            },
            ProductInput: {
                type: 'object',
                required: ['nombre', 'precio'],
                properties: {
                    nombre: { type: 'string', example: 'Teclado' },
                    precio: { type: 'number', example: 29.99 }
                }
            },
            Login: {
                type: 'object',
                required: ['email', 'password'],
                properties: {
                    email: { type: 'string', example: 'alex@correo.com' },
                    password: { type: 'string', example: '123456' }
                }
            },
            Tokens: {
                type: 'object',
                properties: {
                    accessToken: { type: 'string' },
                    refreshToken: { type: 'string' }
                }
            },
            RefreshInput: {
                type: 'object',
                required: ['refreshToken'],
                properties: { refreshToken: { type: 'string' } }
            }
        }
    },
    paths: {
        '/api/auth/register': {
            post: {
                tags: ['Auth'],
                summary: 'Registrar un usuario',
                requestBody: { required: true, ...json(ref('UserInput')) },
                responses: {
                    201: { description: 'Usuario creado', ...json(ref('User')) },
                    409: { description: 'Email ya registrado', ...json(ref('Error')) },
                    ...pick(400, 429)
                }
            }
        },
        '/api/auth/login': {
            post: {
                tags: ['Auth'],
                summary: 'Iniciar sesión (devuelve access y refresh token)',
                requestBody: { required: true, ...json(ref('Login')) },
                responses: {
                    200: { description: 'Tokens', ...json(ref('Tokens')) },
                    401: { description: 'Credenciales incorrectas', ...json(ref('Error')) },
                    ...pick(400, 429)
                }
            }
        },
        '/api/auth/refresh': {
            post: {
                tags: ['Auth'],
                summary: 'Renovar tokens con el refresh token (se rota)',
                requestBody: { required: true, ...json(ref('RefreshInput')) },
                responses: {
                    200: { description: 'Nuevos tokens', ...json(ref('Tokens')) },
                    ...pick(400, 401, 429)
                }
            }
        },
        '/api/auth/logout': {
            post: {
                tags: ['Auth'],
                summary: 'Cerrar sesión (revoca el refresh token)',
                requestBody: { required: true, ...json(ref('RefreshInput')) },
                responses: {
                    200: { description: 'Sesión cerrada' },
                    ...pick(400, 429)
                }
            }
        },
        ...crud('Usuarios', 'users', 'usuario', 'User', 'UserInput'),
        ...crud('Productos', 'products', 'producto', 'Product', 'ProductInput')
    }
}
