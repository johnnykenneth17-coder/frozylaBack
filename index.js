require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

// Helper: verify JWT and get user
async function getUser(req) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return null;
  const {
    data: { user },
    error,
  } = await supabase.auth.getUser(token);
  if (error) return null;
  return user;
}

// Helper: admin check
async function isAdmin(req) {
  const user = await getUser(req);
  if (!user) return false;
  const { data: profile } = await supabase
    .from("profiles")
    .select("role")
    .eq("id", user.id)
    .single();
  return profile?.role === "admin";
}

// ---------- PUBLIC ENDPOINTS ----------
app.get("/api/products", async (req, res) => {
  let query = supabase.from("products").select("*, categories(name)");
  const { category, search, minPrice, maxPrice } = req.query;
  if (category) query = query.eq("category_id", category);
  if (search) query = query.ilike("name", `%${search}%`);
  if (minPrice) query = query.gte("price", parseFloat(minPrice));
  if (maxPrice) query = query.lte("price", parseFloat(maxPrice));
  const { data, error } = await query;
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.get("/api/categories", async (req, res) => {
  const { data, error } = await supabase
    .from("categories")
    .select("*")
    .order("sort_order");
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.get("/api/coupons/:code", async (req, res) => {
  const { code } = req.params;
  const { data, error } = await supabase
    .from("coupons")
    .select("*")
    .eq("code", code)
    .eq("is_active", true)
    .single();
  if (error || !data) return res.status(404).json({ error: "Invalid coupon" });
  res.json(data);
});

// Guest checkout


app.post("/api/orders/guest", async (req, res) => {
  const {
    guest_email,
    guest_name,
    guest_phone,
    items,
    delivery_address,
    payment_method,
    total,
    subtotal,
    tax,
    delivery_fee,
    coupon_code,
    special_instructions,
  } = req.body;
  const { data: order, error } = await supabase
    .from("orders")
    .insert({
      guest_email,
      guest_name,
      guest_phone,
      status: "pending",
      payment_method,
      subtotal,
      delivery_fee,
      tax,
      total,
      coupon_code,
      special_instructions,
      delivery_address_snapshot: delivery_address,
      order_type: "delivery",
    })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  const orderItems = items.map((item) => ({
    order_id: order.id,
    product_id: item.product_id,
    product_name: item.name,
    product_price: item.price,
    quantity: item.quantity,
    customizations: item.customizations || {},
  }));
  const { error: itemsError } = await supabase
    .from("order_items")
    .insert(orderItems);
  if (itemsError) return res.status(500).json({ error: itemsError.message });
  res.json({ order_id: order.id, status: order.status });
});

// Order tracking (public)
app.get("/api/orders/:id", async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from("orders")
    .select("*, order_items(*)")
    .eq("id", id)
    .single();
  if (error) return res.status(404).json({ error: "Order not found" });
  res.json(data);
});

// ---------- AUTHENTICATED USER ENDPOINTS ----------
app.use(async (req, res, next) => {
  const user = await getUser(req);
  if (!user && !req.path.startsWith("/api/admin"))
    return res.status(401).json({ error: "Unauthorized" });
  req.user = user;
  next();
});

// Cart
app.get("/api/cart", async (req, res) => {
  const { data, error } = await supabase
    .from("cart_items")
    .select("*, products(*)")
    .eq("user_id", req.user.id);
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post("/api/cart", async (req, res) => {
  const { product_id, quantity, custom_instructions } = req.body;
  const { data, error } = await supabase
    .from("cart_items")
    .upsert(
      { user_id: req.user.id, product_id, quantity, custom_instructions },
      { onConflict: "user_id,product_id" },
    )
    .select();
  if (error) return res.status(500).json({ error });
  res.json(data[0]);
});

app.delete("/api/cart/:product_id", async (req, res) => {
  const { product_id } = req.params;
  const { error } = await supabase
    .from("cart_items")
    .delete()
    .eq("user_id", req.user.id)
    .eq("product_id", product_id);
  if (error) return res.status(500).json({ error });
  res.json({ success: true });
});

// Addresses
app.get("/api/addresses", async (req, res) => {
  const { data, error } = await supabase
    .from("addresses")
    .select("*")
    .eq("user_id", req.user.id);
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post("/api/addresses", async (req, res) => {
  const { data, error } = await supabase
    .from("addresses")
    .insert({ ...req.body, user_id: req.user.id })
    .select();
  if (error) return res.status(500).json({ error });
  res.json(data[0]);
});

app.put("/api/addresses/:id", async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from("addresses")
    .update(req.body)
    .eq("id", id)
    .eq("user_id", req.user.id)
    .select();
  if (error) return res.status(500).json({ error });
  res.json(data[0]);
});

app.delete("/api/addresses/:id", async (req, res) => {
  const { id } = req.params;
  const { error } = await supabase
    .from("addresses")
    .delete()
    .eq("id", id)
    .eq("user_id", req.user.id);
  if (error) return res.status(500).json({ error });
  res.json({ success: true });
});

// Orders (user)
app.get("/api/my-orders", async (req, res) => {
  const { data, error } = await supabase
    .from("orders")
    .select("*, order_items(*)")
    .eq("user_id", req.user.id)
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post("/api/orders", async (req, res) => {
  const {
    items,
    delivery_address_id,
    payment_method,
    total,
    subtotal,
    tax,
    delivery_fee,
    coupon_code,
    special_instructions,
    scheduled_time,
  } = req.body;
  let addressSnapshot = null;
  if (delivery_address_id) {
    const { data: addr } = await supabase
      .from("addresses")
      .select("*")
      .eq("id", delivery_address_id)
      .single();
    addressSnapshot = addr;
  }
  const { data: order, error } = await supabase
    .from("orders")
    .insert({
      user_id: req.user.id,
      status: "pending",
      payment_method,
      subtotal,
      delivery_fee,
      tax,
      total,
      coupon_code,
      special_instructions,
      scheduled_time,
      delivery_address_id,
      delivery_address_snapshot: addressSnapshot,
      order_type: "delivery",
    })
    .select()
    .single();
  if (error) return res.status(500).json({ error });
  const orderItems = items.map((item) => ({
    order_id: order.id,
    product_id: item.product_id,
    product_name: item.name,
    product_price: item.price,
    quantity: item.quantity,
    customizations: item.customizations || {},
  }));
  const { error: itemsError } = await supabase
    .from("order_items")
    .insert(orderItems);
  if (itemsError) return res.status(500).json({ error: itemsError.message });
  // Clear cart
  await supabase.from("cart_items").delete().eq("user_id", req.user.id);
  res.json({ order_id: order.id, status: order.status });
});

// Reviews
app.get("/api/products/:productId/reviews", async (req, res) => {
  const { productId } = req.params;
  const { data, error } = await supabase
    .from("reviews")
    .select("*, profiles(full_name, avatar_url)")
    .eq("product_id", productId);
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post("/api/reviews", async (req, res) => {
  const { product_id, order_id, rating, comment, images } = req.body;
  const { data, error } = await supabase
    .from("reviews")
    .insert({
      user_id: req.user.id,
      product_id,
      order_id,
      rating,
      comment,
      images,
    })
    .select();
  if (error) return res.status(500).json({ error });
  res.json(data[0]);
});

// Profile
app.get("/api/profile", async (req, res) => {
  const { data, error } = await supabase
    .from("profiles")
    .select("*")
    .eq("id", req.user.id)
    .single();
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.put("/api/profile", async (req, res) => {
  const { full_name, phone, dietary_prefs, avatar_url } = req.body;
  const { data, error } = await supabase
    .from("profiles")
    .update({ full_name, phone, dietary_prefs, avatar_url })
    .eq("id", req.user.id)
    .select();
  if (error) return res.status(500).json({ error });
  res.json(data[0]);
});

// ---------- ADMIN ONLY ENDPOINTS ----------
app.use("/api/admin", async (req, res, next) => {
  if (!(await isAdmin(req)))
    return res.status(403).json({ error: "Admin access required" });
  next();
});

app.get("/api/admin/stats", async (req, res) => {
  const { data: orders } = await supabase
    .from("orders")
    .select("total, status, created_at");
  const { data: products } = await supabase.from("products").select("stock");
  const { count: usersCount } = await supabase
    .from("profiles")
    .select("*", { count: "exact", head: true });
  const totalRevenue =
    orders
      ?.filter((o) => o.status === "delivered")
      .reduce((s, o) => s + o.total, 0) || 0;
  const totalOrders = orders?.length || 0;
  const lowStock = products?.filter((p) => p.stock < 5).length || 0;
  res.json({ totalRevenue, totalOrders, usersCount, lowStock });
});

app.get("/api/admin/orders", async (req, res) => {
  const { data, error } = await supabase
    .from("orders")
    .select("*, order_items(*)")
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.patch("/api/admin/orders/:id/status", async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const { data, error } = await supabase
    .from("orders")
    .update({ status, updated_at: new Date() })
    .eq("id", id)
    .select();
  if (error) return res.status(500).json({ error });
  if (data[0]?.user_id) {
    await supabase.from("notifications").insert({
      user_id: data[0].user_id,
      title: "Order status updated",
      message: `Your order #${id.slice(0, 8)} is now ${status}`,
      type: "order_update",
    });
  }
  res.json(data[0]);
});

// Products CRUD
app.get("/api/admin/products", async (req, res) => {
  const { data, error } = await supabase.from("products").select("*");
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post("/api/admin/products", async (req, res) => {
  const { data, error } = await supabase
    .from("products")
    .insert(req.body)
    .select();
  if (error) return res.status(500).json({ error });
  res.json(data[0]);
});

app.put("/api/admin/products/:id", async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from("products")
    .update(req.body)
    .eq("id", id)
    .select();
  if (error) return res.status(500).json({ error });
  res.json(data[0]);
});

app.delete("/api/admin/products/:id", async (req, res) => {
  const { id } = req.params;
  const { error } = await supabase.from("products").delete().eq("id", id);
  if (error) return res.status(500).json({ error });
  res.json({ success: true });
});

// Users list (admin)
app.get("/api/admin/users", async (req, res) => {
  const { data, error } = await supabase.from("profiles").select("*");
  if (error) return res.status(500).json({ error });
  res.json(data);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`✅ Frozyla backend running on port ${PORT}`),
);


// ---------- Admin Coupon CRUD ----------
app.get('/api/admin/coupons', async (req, res) => {
  const { data, error } = await supabase.from('coupons').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post('/api/admin/coupons', async (req, res) => {
  const { data, error } = await supabase.from('coupons').insert(req.body).select();
  if (error) return res.status(500).json({ error });
  res.json(data[0]);
});

app.put('/api/admin/coupons/:id', async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase.from('coupons').update(req.body).eq('id', id).select();
  if (error) return res.status(500).json({ error });
  res.json(data[0]);
});

app.delete('/api/admin/coupons/:id', async (req, res) => {
  const { id } = req.params;
  const { error } = await supabase.from('coupons').delete().eq('id', id);
  if (error) return res.status(500).json({ error });
  res.json({ success: true });
});

// ---------- Delivery partners (simple) ----------
app.get('/api/admin/delivery-partners', async (req, res) => {
  // For demo, return mock data; you can create a 'delivery_partners' table
  res.json([{ id: 1, name: 'John Doe', phone: '+123456789', zone: 'North', status: 'active' }]);
});
