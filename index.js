const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

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

// Helper functions
function generateOrderNumber() {
    return 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6).toUpperCase();
}

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

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user in Supabase Auth with custom approach
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
        console.error('Registration error:', error);
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

        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', authData.user.id)
            .single();

        if (profileError) throw profileError;

        const token = jwt.sign(
            { id: profile.id, email: profile.email, role: profile.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ token, user: profile });
    } catch (error) {
        console.error('Login error:', error);
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Add this after your existing auth routes

// Admin login with special handling
app.post('/api/auth/admin-login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // First, try to authenticate with Supabase Auth
        const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
            email,
            password,
        });

        if (authError) {
            console.error('Auth error:', authError);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Get user profile
        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', authData.user.id)
            .single();

        if (profileError) {
            console.error('Profile error:', profileError);
            return res.status(401).json({ error: 'User profile not found' });
        }

        // Check if user is admin
        if (profile.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        // Generate new JWT with updated role
        const token = jwt.sign(
            { id: profile.id, email: profile.email, role: profile.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ 
            token, 
            user: profile,
            message: 'Admin login successful'
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Refresh user token (to get updated role)
app.post('/api/auth/refresh-token', authenticateToken, async (req, res) => {
    try {
        // Get fresh user data from database
        const { data: profile, error } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', req.user.id)
            .single();

        if (error) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Generate new token with updated role
        const newToken = jwt.sign(
            { id: profile.id, email: profile.email, role: profile.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ 
            token: newToken, 
            user: profile 
        });
    } catch (error) {
        console.error('Token refresh error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Direct role update for admin (use with caution)
app.put('/api/admin/update-role/:userId', authenticateToken, requireAdmin, async (req, res) => {
    const { userId } = req.params;
    const { role } = req.body;

    if (!['user', 'admin'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
    }

    try {
        const { data, error } = await supabase
            .from('profiles')
            .update({ role, updated_at: new Date() })
            .eq('id', userId)
            .select()
            .single();

        if (error) {
            return res.status(500).json({ error: error.message });
        }

        res.json({ message: 'Role updated successfully', user: data });
    } catch (error) {
        console.error('Role update error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Debug endpoint to check user role (for troubleshooting)
app.get('/api/debug/user-role', authenticateToken, async (req, res) => {
    try {
        const { data: profile, error } = await supabase
            .from('profiles')
            .select('id, email, role')
            .eq('id', req.user.id)
            .single();

        if (error) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            user_id: profile.id,
            email: profile.email,
            role: profile.role,
            token_role: req.user.role
        });
    } catch (error) {
        console.error('Debug error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Categories Routes
app.get('/api/categories', async (req, res) => {
    const { data, error } = await supabase
        .from('categories')
        .select('*')
        .order('name');

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

// Products Routes
app.get('/api/products', async (req, res) => {
    const { category, search, vegan, gluten_free, min_price, max_price } = req.query;
    
    let query = supabase.from('products').select('*');

    if (category && category !== 'all') {
        query = query.eq('category_id', category);
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
        .select('*')
        .eq('id', req.params.id)
        .single();

    if (error) {
        return res.status(404).json({ error: 'Product not found' });
    }
    res.json(data);
});

app.post('/api/products', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const productData = {
            ...req.body,
            price: parseFloat(req.body.price),
            stock_quantity: parseInt(req.body.stock_quantity),
            is_vegan: req.body.is_vegan === 'true',
            is_gluten_free: req.body.is_gluten_free === 'true'
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

// Cart Sync Routes
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
    
    const order_number = generateOrderNumber();
    
    // Create order
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
        
        if (product) {
            await supabase
                .from('products')
                .update({ stock_quantity: Math.max(0, product.stock_quantity - item.quantity) })
                .eq('id', item.id);
        }
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
    
    // Check if user already reviewed
    const { data: existing } = await supabase
        .from('reviews')
        .select('id')
        .eq('product_id', req.params.productId)
        .eq('user_id', req.user.id)
        .single();
    
    if (existing) {
        // Update existing review
        const { data, error } = await supabase
            .from('reviews')
            .update({ rating, comment, updated_at: new Date() })
            .eq('id', existing.id)
            .select()
            .single();
        
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        return res.json(data);
    }
    
    // Create new review
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
    
    const { count: totalUsers } = await supabase
        .from('profiles')
        .select('*', { count: 'exact', head: true });
    
    const total_sales = orders?.reduce((sum, order) => sum + (order.status !== 'cancelled' ? order.total_amount : 0), 0) || 0;
    const pending_orders = orders?.filter(order => order.status === 'pending').length || 0;
    
    res.json({
        total_sales,
        total_orders: orders?.length || 0,
        total_users: totalUsers || 0,
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

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// For Vercel serverless deployment
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

module.exports = app;