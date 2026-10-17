export const swaggerSpec = {
  "openapi": "3.0.0",
  "info": {
    "title": "REST API - Engine Scrapyard",
    "version": "1.0.0",
    "description": "GET requests are public. POST, PUT and DELETE need the access token (Authorize button). Limit: 100 requests every 15 minutes per IP."
  },
  "components": {
    "schemas": {
      "Engine": {
        "type": "object",
        "properties": {
          "marca": { "type": "string", "description": "Brand", "example": "Renault" },
          "modelo": { "type": "string", "description": "Model", "example": "K9K 1.5 dCi" },
          "cilindrada": { "type": "integer", "description": "Displacement in cc", "example": 1461 },
          "combustible": { "type": "string", "description": "Fuel type", "example": "Diesel" },
          "kilometros": { "type": "integer", "description": "Mileage in km", "example": 120000 },
          "precio": { "type": "number", "description": "Price in euros", "example": 850 }
        }
      }
    },
    "securitySchemes": {
      "bearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" }
    },
    "parameters": {
      "id": { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
    }
  },
  "paths": {
    "/api/login": {
      "post": {
        "tags": ["Authentication"],
        "summary": "Log in (returns accessToken and refreshToken)",
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": {
            "type": "object",
            "properties": {
              "nombre": { "type": "string", "description": "Username", "example": "Alex" },
              "password": { "type": "string", "example": "123456" }
            }
          } } }
        },
        "responses": {
          "200": { "description": "accessToken (15 min) and refreshToken (7 days)" },
          "401": { "description": "Incorrect username or password" }
        }
      }
    },
    "/api/refresh": {
      "post": {
        "tags": ["Authentication"],
        "summary": "Get a new access token using the refresh token",
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": {
            "type": "object",
            "properties": { "refreshToken": { "type": "string" } }
          } } }
        },
        "responses": {
          "200": { "description": "New accessToken" },
          "401": { "description": "Invalid or expired refresh token" }
        }
      }
    },
    "/api/users": {
      "get": {
        "tags": ["Users"],
        "summary": "List users",
        "responses": { "200": { "description": "List of users" } }
      },
      "post": {
        "tags": ["Users"],
        "summary": "Create a user",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": {
            "type": "object",
            "properties": {
              "nombre": { "type": "string", "description": "Username", "example": "Ana" },
              "edad": { "type": "integer", "description": "Age", "example": 22 },
              "password": { "type": "string", "example": "123456" }
            }
          } } }
        },
        "responses": {
          "201": { "description": "User created" },
          "401": { "description": "Invalid token" },
          "409": { "description": "The user already exists" }
        }
      }
    },
    "/api/users/{id}": {
      "get": {
        "tags": ["Users"],
        "summary": "Get a user",
        "parameters": [{ "$ref": "#/components/parameters/id" }],
        "responses": {
          "200": { "description": "User" },
          "404": { "description": "Not found" }
        }
      },
      "put": {
        "tags": ["Users"],
        "summary": "Update a user",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "$ref": "#/components/parameters/id" }],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": {
            "type": "object",
            "properties": {
              "nombre": { "type": "string", "description": "Username", "example": "Ana" },
              "edad": { "type": "integer", "description": "Age", "example": 23 }
            }
          } } }
        },
        "responses": {
          "200": { "description": "User updated" },
          "401": { "description": "Invalid token" }
        }
      },
      "delete": {
        "tags": ["Users"],
        "summary": "Delete a user",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "$ref": "#/components/parameters/id" }],
        "responses": {
          "200": { "description": "User deleted" },
          "401": { "description": "Invalid token" }
        }
      }
    },
    "/api/motores": {
      "get": {
        "tags": ["Engines"],
        "summary": "List the engines in the scrapyard",
        "responses": { "200": { "description": "List of engines" } }
      },
      "post": {
        "tags": ["Engines"],
        "summary": "Add an engine",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Engine" } } }
        },
        "responses": {
          "201": { "description": "Engine added" },
          "401": { "description": "Invalid token" }
        }
      }
    },
    "/api/motores/{id}": {
      "get": {
        "tags": ["Engines"],
        "summary": "Get an engine",
        "parameters": [{ "$ref": "#/components/parameters/id" }],
        "responses": {
          "200": { "description": "Engine" },
          "404": { "description": "Not found" }
        }
      },
      "put": {
        "tags": ["Engines"],
        "summary": "Update an engine",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "$ref": "#/components/parameters/id" }],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Engine" } } }
        },
        "responses": {
          "200": { "description": "Engine updated" },
          "401": { "description": "Invalid token" }
        }
      },
      "delete": {
        "tags": ["Engines"],
        "summary": "Delete an engine",
        "security": [{ "bearerAuth": [] }],
        "parameters": [{ "$ref": "#/components/parameters/id" }],
        "responses": {
          "200": { "description": "Engine deleted" },
          "401": { "description": "Invalid token" }
        }
      }
    }
  }
}