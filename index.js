const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Supabase client - IMPORTANT: Use service role key for admin operations
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
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

// Helper function to generate order number
function generateOrderNumber() {
    return 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6).toUpperCase();
}

// ============ AUTH ROUTES ============

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
    const { email, password, full_name } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        // Create user in Supabase Auth
        const { data: authData, error: authError } = await supabase.auth.signUp({
            email,
            password,
            options: {
                data: {
                    full_name: full_name || email.split('@')[0]
                }
            }
        });

        if (authError) {
            console.error('Auth signup error:', authError);
            return res.status(400).json({ error: authError.message });
        }

        if (!authData.user) {
            return res.status(400).json({ error: 'Failed to create user' });
        }

        // Create profile in public.profiles table
        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .insert([{
                id: authData.user.id,
                email: email,
                full_name: full_name || email.split('@')[0],
                role: 'user'
            }])
            .select()
            .single();

        if (profileError) {
            console.error('Profile creation error:', profileError);
            // Try to delete the auth user if profile creation fails
            await supabase.auth.admin.deleteUser(authData.user.id);
            return res.status(500).json({ error: 'Failed to create user profile' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: profile.id, email: profile.email, role: profile.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({ 
            token, 
            user: profile,
            message: 'Registration successful'
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        // Sign in with Supabase Auth
        const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
            email,
            password,
        });

        if (authError) {
            console.error('Login auth error:', authError);
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        if (!authData.user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Get user profile from public.profiles
        let { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', authData.user.id)
            .single();

        // If profile doesn't exist, create it
        if (profileError && profileError.code === 'PGRST116') {
            const { data: newProfile, error: createError } = await supabase
                .from('profiles')
                .insert([{
                    id: authData.user.id,
                    email: email,
                    full_name: authData.user.user_metadata?.full_name || email.split('@')[0],
                    role: 'user'
                }])
                .select()
                .single();

            if (createError) {
                console.error('Profile creation on login error:', createError);
                return res.status(500).json({ error: 'Failed to get user profile' });
            }
            profile = newProfile;
        } else if (profileError) {
            console.error('Profile fetch error:', profileError);
            return res.status(500).json({ error: 'Failed to get user profile' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: profile.id, email: profile.email, role: profile.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ 
            token, 
            user: profile,
            message: 'Login successful'
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Admin login endpoint
app.post('/api/auth/admin-login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Sign in with Supabase Auth
        const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
            email,
            password,
        });

        if (authError) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Get user profile
        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', authData.user.id)
            .single();

        if (profileError) {
            return res.status(404).json({ error: 'User profile not found' });
        }

        // Check if user is admin
        if (profile.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        // Generate JWT
        const token = jwt.sign(
            { id: profile.id, email: profile.email, role: profile.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ token, user: profile });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get current user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { data: profile, error } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', req.user.id)
            .single();

        if (error) {
            return res.status(404).json({ error: 'Profile not found' });
        }

        res.json(profile);
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update user profile
app.put('/api/profile', authenticateToken, async (req, res) => {
    const { full_name, phone, address, city, postal_code } = req.body;
    
    try {
        const { data, error } = await supabase
            .from('profiles')
            .update({ 
                full_name, 
                phone, 
                address, 
                city, 
                postal_code, 
                updated_at: new Date() 
            })
            .eq('id', req.user.id)
            .select()
            .single();

        if (error) {
            return res.status(500).json({ error: error.message });
        }

        res.json(data);
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Refresh token
app.post('/api/auth/refresh-token', authenticateToken, async (req, res) => {
    try {
        const { data: profile, error } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', req.user.id)
            .single();

        if (error) {
            return res.status(404).json({ error: 'User not found' });
        }

        const newToken = jwt.sign(
            { id: profile.id, email: profile.email, role: profile.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ token: newToken, user: profile });
    } catch (error) {
        console.error('Token refresh error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Debug endpoint
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

// ============ CATEGORIES ROUTES ============

app.get('/api/categories', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('categories')
            .select('*')
            .order('name');

        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============ PRODUCTS ROUTES ============

app.get('/api/products', async (req, res) => {
    const { category, search, vegan, gluten_free, min_price, max_price } = req.query;
    
    try {
        let query = supabase.from('products').select('*');

        if (category && category !== 'all' && category !== 'undefined') {
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
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Products fetch error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('products')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (error) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/products', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const productData = {
            name: req.body.name,
            description: req.body.description,
            price: parseFloat(req.body.price),
            category_id: req.body.category_id,
            image_url: req.body.image_url,
            stock_quantity: parseInt(req.body.stock_quantity) || 0,
            is_vegan: req.body.is_vegan === 'true' || req.body.is_vegan === true,
            is_gluten_free: req.body.is_gluten_free === 'true' || req.body.is_gluten_free === true
        };
        
        const { data, error } = await supabase
            .from('products')
            .insert([productData])
            .select()
            .single();
        
        if (error) throw error;
        res.json(data);
    } catch (error) {
        console.error('Product creation error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/products/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { error } = await supabase
            .from('products')
            .delete()
            .eq('id', req.params.id);

        if (error) throw error;
        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============ CART ROUTES ============

app.post('/api/cart/sync', authenticateToken, async (req, res) => {
    const { items } = req.body;
    
    try {
        // Clear existing cart
        await supabase.from('cart_items').delete().eq('user_id', req.user.id);
        
        if (items && items.length > 0) {
            // Insert new items
            const cartItems = items.map(item => ({
                user_id: req.user.id,
                product_id: item.id,
                quantity: item.quantity,
                size_variant: item.size_variant || null
            }));
            
            const { data, error } = await supabase
                .from('cart_items')
                .insert(cartItems)
                .select();

            if (error) throw error;
            res.json(data);
        } else {
            res.json([]);
        }
    } catch (error) {
        console.error('Cart sync error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/cart/sync', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cart_items')
            .select('*, products(*)')
            .eq('user_id', req.user.id);

        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============ ORDERS ROUTES ============

app.post('/api/orders', authenticateToken, async (req, res) => {
    const { items, shipping_address, shipping_city, shipping_postal_code, total_amount } = req.body;
    
    const order_number = generateOrderNumber();
    
    try {
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
                payment_method: 'card',
                payment_status: 'paid'
            }])
            .select()
            .single();

        if (orderError) throw orderError;
        
        // Insert order items
        const orderItems = items.map(item => ({
            order_id: order.id,
            product_id: item.id,
            product_name: item.name,
            quantity: item.quantity,
            price_at_time: item.price,
            size_variant: item.size_variant || null
        }));
        
        const { error: itemsError } = await supabase
            .from('order_items')
            .insert(orderItems);

        if (itemsError) throw itemsError;
        
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
    } catch (error) {
        console.error('Order creation error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        let query = supabase
            .from('orders')
            .select('*, order_items(*)')
            .order('created_at', { ascending: false });
        
        if (req.user.role !== 'admin') {
            query = query.eq('user_id', req.user.id);
        }
        
        const { data, error } = await query;
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Orders fetch error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/orders/:id/status', authenticateToken, requireAdmin, async (req, res) => {
    const { status } = req.body;
    
    try {
        const { data, error } = await supabase
            .from('orders')
            .update({ status, updated_at: new Date() })
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============ REVIEWS ROUTES ============

app.get('/api/products/:productId/reviews', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('reviews')
            .select('*, profiles(full_name)')
            .eq('product_id', req.params.productId)
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/products/:productId/reviews', authenticateToken, async (req, res) => {
    const { rating, comment } = req.body;
    
    try {
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
            
            if (error) throw error;
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

        if (error) throw error;
        res.json(data);
    } catch (error) {
        console.error('Review submission error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============ WISHLIST ROUTES ============

app.get('/api/wishlist', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('wishlist')
            .select('*, products(*)')
            .eq('user_id', req.user.id);

        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/wishlist', authenticateToken, async (req, res) => {
    const { product_id } = req.body;
    
    try {
        const { data, error } = await supabase
            .from('wishlist')
            .insert([{
                user_id: req.user.id,
                product_id
            }])
            .select()
            .single();

        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/wishlist/:productId', authenticateToken, async (req, res) => {
    try {
        const { error } = await supabase
            .from('wishlist')
            .delete()
            .eq('user_id', req.user.id)
            .eq('product_id', req.params.productId);

        if (error) throw error;
        res.json({ message: 'Removed from wishlist' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============ ADMIN ROUTES ============

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
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
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/orders', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('orders')
            .select('*, order_items(*), profiles(full_name, email)')
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server (for local development)
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

module.exports = app;