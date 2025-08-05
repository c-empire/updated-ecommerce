const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const mongoosePaginate = require('mongoose-paginate-v2'); // ✅ ADDED

dotenv.config();

const app = express();
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://ecommerce:emperor234@node.m5ivxkf.mongodb.net/?retryWrites=true&w=majority&appName=node', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'customer'], required: true }
});
const User = mongoose.model('User', userSchema);

// Brand Schema
const brandSchema = new mongoose.Schema({
  brandName: { type: String, required: true, unique: true }
});
const Brand = mongoose.model('Brand', brandSchema);

// Product Schema
const productSchema = new mongoose.Schema({
  productName: { type: String, required: true },
  brand: { type: mongoose.Schema.Types.ObjectId, ref: 'Brand' },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  cost: { type: Number, required: true },
  productImages: [{ type: String }],
  description: { type: String, required: true },
  stockStatus: { type: String, required: true }
});
productSchema.plugin(mongoosePaginate);
const ProductModel = mongoose.model('Product', productSchema);

// Middleware to verify JWT
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Middleware to check if user is admin
const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// POST /brands
app.post('/brands', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { brandName } = req.body;
    const brand = new Brand({ brandName });
    await brand.save();
    res.status(201).json(brand);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /brands/:id
app.put('/brands/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const brand = await Brand.findByIdAndUpdate(req.params.id, { brandName: req.body.brandName }, { new: true });
    if (!brand) return res.status(404).json({ message: 'Brand not found' });
    res.json(brand);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /brands
app.get('/brands', async (req, res) => {
  try {
    const brands = await Brand.find();
    res.json(brands);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /brands/:id
app.delete('/brands/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await Brand.findByIdAndDelete(req.params.id);
    res.json({ message: 'Brand deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Register
app.post('/auth/register', async (req, res) => {
  try {
    const { fullName, email, password, role } = req.body;

    if (!['admin', 'customer'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ fullName, email, password: hashedPassword, role });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user', error: error.message });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'secretkey',
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

// Get all products
app.get('/products', async (req, res) => {
  try {
    const products = await ProductModel.find().populate('ownerId', 'fullName email').populate('brand', 'brandName');
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching products', error: error.message });
  }
});

// Get paginated products by brand
app.get('/products/:brand/:page/:limit', async (req, res) => {
  const { brand, page, limit } = req.params;
  try {
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      populate: ['brand', 'ownerId']
    };
    const result = await ProductModel.paginate({ brand }, options);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create product
app.post('/products', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { productName, cost, productImages, description, stockStatus, brand } = req.body;

    const product = new ProductModel({
      productName,
      ownerId: req.user.userId,
      brand,
      cost,
      productImages,
      description,
      stockStatus
    });

    await product.save();
    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ message: 'Error creating product', error: error.message });
  }
});

// Delete product
app.delete('/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const product = await ProductModel.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found' });

    if (product.ownerId.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Not authorized to delete this product' });
    }

    await ProductModel.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting product', error: error.message });
  }
});

app.listen(3000, () => {
  console.log("server has started on port 3000");
});
