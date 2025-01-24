const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();

app.use(express.json());

// Configuration CORS
const corsOptions = {
  origin: ['http://example.com', 'http://localhost:4000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};
app.use(cors(corsOptions));

// Version de l'API
const API_VERSION = '/v2';

// Clé secrète pour JWT
const JWT_SECRET = 'verysecretkey';
const JWT_EXPIRATION = '1h';

// Données utilisateur simulées
let users = [
  { id: 1, name: 'Admin User', email: 'admin@example.com', password: bcrypt.hashSync('admin123', 10), role: 'admin' },
  { id: 2, name: 'Regular User', email: 'user@example.com', password: bcrypt.hashSync('user123', 10), role: 'user' },
];

// Données produits simulées
let products = [
  { id: 1, name: 'Product A', description: 'Description of Product A', price: 100, stock: 10 },
  { id: 2, name: 'Product B', description: 'Description of Product B', price: 200, stock: 5 },
];

// Middleware pour vérifier le token JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access token is missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Middleware pour vérifier si l'utilisateur est admin
function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admins only.' });
  }
  next();
}

// Configuration Swagger
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API Documentation',
      version: '1.0.0',
      description: 'Documentation for the Express API',
    },
    servers: [
      {
        url: 'http://localhost:3000/v2',
        description: 'Local server',
      },
    ],
  },
  apis: ['./api-products.js'], // Indiquez le chemin vers ce fichier si vous utilisez swagger-jsdoc
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - name
 *         - email
 *         - password
 *         - role
 *       properties:
 *         id:
 *           type: integer
 *           description: Auto-generated ID
 *         name:
 *           type: string
 *           description: User's name
 *         email:
 *           type: string
 *           description: User's email
 *         password:
 *           type: string
 *           description: User's password
 *         role:
 *           type: string
 *           description: User's role
 *     Product:
 *       type: object
 *       required:
 *         - name
 *         - description
 *         - price
 *         - stock
 *       properties:
 *         id:
 *           type: integer
 *           description: Auto-generated ID
 *         name:
 *           type: string
 *           description: Product name
 *         description:
 *           type: string
 *           description: Product description
 *         price:
 *           type: number
 *           description: Product price
 *         stock:
 *           type: integer
 *           description: Product stock
 */

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Missing required fields
 *       409:
 *         description: User with this email already exists
 */
app.post(`${API_VERSION}/auth/register`, async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: 'Missing required fields: name, email, password, role' });
  }

  const existingUser = users.find((u) => u.email === email);
  if (existingUser) {
    return res.status(409).json({ message: 'User with this email already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = { id: users.length + 1, name, email, password: hashedPassword, role };
  users.push(newUser);

  res.status(201).json({ message: 'User registered successfully', user: { id: newUser.id, name, email, role } });
});

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login a user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Successful login
 *       401:
 *         description: Invalid email or password
 */
app.post(`${API_VERSION}/auth/login`, async (req, res) => {
  const { email, password } = req.body;

  const user = users.find((u) => u.email === email);
  if (!user) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRATION });

  res.status(200).json({ token });
});

/**
 * @swagger
 * /products:
 *   get:
 *     summary: Get all products
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all products
 */
app.get(`${API_VERSION}/products`, authenticateToken, (req, res) => {
  res.status(200).json({ success: true, total: products.length, data: products });
});

/**
 * @swagger
 * /products/{id}:
 *   get:
 *     summary: Get a product by ID
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: ID of the product to get
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Product details
 *       404:
 *         description: Product not found
 */
app.get(`${API_VERSION}/products/:id`, authenticateToken, (req, res) => {
  const productId = parseInt(req.params.id, 10);
  const product = products.find((p) => p.id === productId);

  if (!product) {
    return res.status(404).json({ message: `Product with ID ${productId} not found` });
  }

  res.status(200).json({ success: true, data: product });
});

/**
 * @swagger
 * /products:
 *   post:
 *     summary: Add a new product
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               price:
 *                 type: number
 *               stock:
 *                 type: integer
 *     responses:
 *       201:
 *         description: Product added successfully
 *       400:
 *         description: Missing required fields
 */
app.post(`${API_VERSION}/products`, authenticateToken, isAdmin, (req, res) => {
  const { name, description, price, stock } = req.body;

  if (!name || !description || !price || !stock) {
    return res.status(400).json({ message: 'Missing required fields: name, description, price, stock' });
  }

  const newProduct = { id: products.length + 1, name, description, price, stock };
  products.push(newProduct);

  res.status(201).json({ success: true, data: newProduct });
});

/**
 * @swagger
 * /products/{id}:
 *   put:
 *     summary: Update a product
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *           description: The ID of the product to update
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               price:
 *                 type: number
 *               stock:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Product updated successfully
 *       404:
 *         description: Product not found
 */
app.put(`${API_VERSION}/products/:id`, authenticateToken, isAdmin, (req, res) => {
  const productId = parseInt(req.params.id, 10);
  const { name, description, price, stock } = req.body;

  const product = products.find((p) => p.id === productId);
  if (!product) {
    return res.status(404).json({ message: `Product with ID ${productId} not found` });
  }

  if (name) product.name = name;
  if (description) product.description = description;
  if (price) product.price = price;
  if (stock) product.stock = stock;

  res.status(200).json({ success: true, data: product });
});

/**
 * @swagger
 * /products/{id}:
 *   delete:
 *     summary: Delete a product
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *           description: The ID of the product to delete
 *     responses:
 *       204:
 *         description: Product deleted successfully
 *       404:
 *         description: Product not found
 */
app.delete(`${API_VERSION}/products/:id`, authenticateToken, isAdmin, (req, res) => {
  const productId = parseInt(req.params.id, 10);

  const productIndex = products.findIndex((p) => p.id === productId);
  if (productIndex === -1) {
    return res.status(404).json({ message: `Product with ID ${productId} not found` });
  }

  products.splice(productIndex, 1);

  res.status(204).send();
});




// --- Lancer le serveur ---
app.listen(3000, () => {
  console.log(`API ${API_VERSION} is running on http://localhost:3000`);
  console.log('Swagger UI is running on http://localhost:3000/api-docs');
});
