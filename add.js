const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// File upload setup
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

const requireAdmin = async (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    const { email, password, full_name } = req.body;

    try {
        // Check if user exists
        const { data: existingUser } = await supabase
            .from('profiles')
            .select('email')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Create user in Supabase Auth
        const { data: authData, error: authError } = await supabase.auth.signUp({
            email,
            password,
        });

        if (authError) throw authError;

        // Create profile
        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .insert([{
                id: authData.user.id,
                email,
                full_name,
                role: 'user'
            }])
            .select()
            .single();

        if (profileError) throw profileError;

        // Generate JWT
        const token = jwt.sign(
            { id: profile.id, email: profile.email, role: profile.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ token, user: profile });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
            email,
            password,
        });

        if (authError) throw authError;

        const { data: profile } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', authData.user.id)
            .single();

        const token = jwt.sign(
            { id: profile.id, email: profile.email, role: profile.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ token, user: profile });
    } catch (error) {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Products Routes
app.get('/api/products', async (req, res) => {
    const { category, search, vegan, gluten_free, min_price, max_price } = req.query;
    
    let query = supabase.from('products').select('*, categories(name, slug)');

    if (category && category !== 'all') {
        query = query.eq('categories.slug', category);
    }
    if (search) {
        query = query.ilike('name', `%${search}%`);
    }
    if (vegan === 'true') {
        query = query.eq('is_vegan', true);
    }
    if (gluten_free === 'true') {
        query = query.eq('is_gluten_free', true);
    }
    if (min_price) {
        query = query.gte('price', parseFloat(min_price));
    }
    if (max_price) {
        query = query.lte('price', parseFloat(max_price));
    }

    const { data, error } = await query;
    
    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

app.get('/api/products/:id', async (req, res) => {
    const { data, error } = await supabase
        .from('products')
        .select('*, categories(name, slug)')
        .eq('id', req.params.id)
        .single();

    if (error) {
        return res.status(404).json({ error: 'Product not found' });
    }
    res.json(data);
});

app.post('/api/products', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
    try {
        let image_url = req.body.image_url;
        
        if (req.file) {
            // Upload to Supabase Storage
            const file = req.file;
            const fileName = `${Date.now()}-${file.originalname}`;
            const { data: uploadData, error: uploadError } = await supabase.storage
                .from('product-images')
                .upload(fileName, file.buffer, {
                    contentType: file.mimetype
                });
            
            if (uploadError) throw uploadError;
            
            const { data: { publicUrl } } = supabase.storage
                .from('product-images')
                .getPublicUrl(fileName);
            
            image_url = publicUrl;
        }
        
        const productData = {
            ...req.body,
            image_url,
            price: parseFloat(req.body.price),
            stock_quantity: parseInt(req.body.stock_quantity),
            is_vegan: req.body.is_vegan === 'true',
            is_gluten_free: req.body.is_gluten_free === 'true',
            size_variants: req.body.size_variants ? JSON.parse(req.body.size_variants) : null,
            nutritional_info: req.body.nutritional_info ? JSON.parse(req.body.nutritional_info) : null
        };
        
        const { data, error } = await supabase
            .from('products')
            .insert([productData])
            .select()
            .single();
        
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/products/:id', authenticateToken, requireAdmin, async (req, res) => {
    const { data, error } = await supabase
        .from('products')
        .update(req.body)
        .eq('id', req.params.id)
        .select()
        .single();

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

app.delete('/api/products/:id', authenticateToken, requireAdmin, async (req, res) => {
    const { error } = await supabase
        .from('products')
        .delete()
        .eq('id', req.params.id);

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json({ message: 'Product deleted successfully' });
});

// Cart Routes (using localStorage on frontend, but we'll sync)
app.get('/api/cart/sync', authenticateToken, async (req, res) => {
    const { data: cartItems, error } = await supabase
        .from('cart_items')
        .select('*, products(*)')
        .eq('user_id', req.user.id);

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(cartItems);
});

app.post('/api/cart/sync', authenticateToken, async (req, res) => {
    const { items } = req.body;
    
    // Clear existing cart
    await supabase.from('cart_items').delete().eq('user_id', req.user.id);
    
    // Insert new items
    const cartItems = items.map(item => ({
        user_id: req.user.id,
        product_id: item.id,
        quantity: item.quantity,
        size_variant: item.size_variant
    }));
    
    const { data, error } = await supabase
        .from('cart_items')
        .insert(cartItems)
        .select();

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

// Orders Routes
app.post('/api/orders', authenticateToken, async (req, res) => {
    const { items, shipping_address, shipping_city, shipping_postal_code, total_amount } = req.body;
    
    const order_number = 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6);
    
    // Start a transaction
    const { data: order, error: orderError } = await supabase
        .from('orders')
        .insert([{
            user_id: req.user.id,
            order_number,
            status: 'pending',
            total_amount,
            shipping_address,
            shipping_city,
            shipping_postal_code,
            payment_method: 'simulated',
            payment_status: 'paid'
        }])
        .select()
        .single();

    if (orderError) {
        return res.status(500).json({ error: orderError.message });
    }
    
    // Insert order items
    const orderItems = items.map(item => ({
        order_id: order.id,
        product_id: item.id,
        product_name: item.name,
        quantity: item.quantity,
        price_at_time: item.price,
        size_variant: item.size_variant
    }));
    
    const { error: itemsError } = await supabase
        .from('order_items')
        .insert(orderItems);

    if (itemsError) {
        return res.status(500).json({ error: itemsError.message });
    }
    
    // Update product stock
    for (const item of items) {
        const { data: product } = await supabase
            .from('products')
            .select('stock_quantity')
            .eq('id', item.id)
            .single();
        
        await supabase
            .from('products')
            .update({ stock_quantity: product.stock_quantity - item.quantity })
            .eq('id', item.id);
    }
    
    // Clear cart after order
    await supabase.from('cart_items').delete().eq('user_id', req.user.id);
    
    res.json(order);
});

app.get('/api/orders', authenticateToken, async (req, res) => {
    let query = supabase
        .from('orders')
        .select('*, order_items(*)')
        .order('created_at', { ascending: false });
    
    if (req.user.role !== 'admin') {
        query = query.eq('user_id', req.user.id);
    }
    
    const { data, error } = await query;
    
    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

app.put('/api/orders/:id/status', authenticateToken, requireAdmin, async (req, res) => {
    const { status } = req.body;
    
    const { data, error } = await supabase
        .from('orders')
        .update({ status, updated_at: new Date() })
        .eq('id', req.params.id)
        .select()
        .single();

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

// Reviews Routes
app.get('/api/products/:productId/reviews', async (req, res) => {
    const { data, error } = await supabase
        .from('reviews')
        .select('*, profiles(full_name)')
        .eq('product_id', req.params.productId)
        .order('created_at', { ascending: false });

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

app.post('/api/products/:productId/reviews', authenticateToken, async (req, res) => {
    const { rating, comment } = req.body;
    
    const { data, error } = await supabase
        .from('reviews')
        .insert([{
            product_id: req.params.productId,
            user_id: req.user.id,
            rating,
            comment
        }])
        .select()
        .single();

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

// Wishlist Routes
app.get('/api/wishlist', authenticateToken, async (req, res) => {
    const { data, error } = await supabase
        .from('wishlist')
        .select('*, products(*)')
        .eq('user_id', req.user.id);

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

app.post('/api/wishlist', authenticateToken, async (req, res) => {
    const { product_id } = req.body;
    
    const { data, error } = await supabase
        .from('wishlist')
        .insert([{
            user_id: req.user.id,
            product_id
        }])
        .select()
        .single();

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

app.delete('/api/wishlist/:productId', authenticateToken, async (req, res) => {
    const { error } = await supabase
        .from('wishlist')
        .delete()
        .eq('user_id', req.user.id)
        .eq('product_id', req.params.productId);

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json({ message: 'Removed from wishlist' });
});

// Admin Dashboard Routes
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    const { data: orders } = await supabase
        .from('orders')
        .select('total_amount, status');
    
    const { data: users } = await supabase
        .from('profiles')
        .select('id', { count: 'exact' });
    
    const total_sales = orders?.reduce((sum, order) => sum + (order.status !== 'cancelled' ? order.total_amount : 0), 0) || 0;
    const pending_orders = orders?.filter(order => order.status === 'pending').length || 0;
    
    res.json({
        total_sales,
        total_orders: orders?.length || 0,
        total_users: users?.length || 0,
        pending_orders
    });
});

app.get('/api/admin/orders', authenticateToken, requireAdmin, async (req, res) => {
    const { data, error } = await supabase
        .from('orders')
        .select('*, order_items(*), profiles(full_name, email)')
        .order('created_at', { ascending: false });

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

// Profile Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
    const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', req.user.id)
        .single();

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    const { full_name, phone, address, city, postal_code } = req.body;
    
    const { data, error } = await supabase
        .from('profiles')
        .update({ full_name, phone, address, city, postal_code, updated_at: new Date() })
        .eq('id', req.user.id)
        .select()
        .single();

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});