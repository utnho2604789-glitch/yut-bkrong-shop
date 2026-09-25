const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_SECRET';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'CHANGE_THIS_ADMIN_PASSWORD';

const root = __dirname;
const uploadsDir = path.join(root, 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });
const db = new Database(path.join(root, 'database.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(fs.readFileSync(path.join(root, 'database.sql'), 'utf8'));

const upload = multer({
  dest: uploadsDir,
  limits: { fileSize: 25 * 1024 * 1024 }
});

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(root));

function tokenFor(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Chưa đăng nhập' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Phiên đăng nhập hết hạn' }); }
}
function admin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Không có quyền admin' });
  next();
}
function money(n) { return Number(n); }

app.post('/api/register', (req,res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6) return res.status(400).json({error:'Thông tin không hợp lệ'});
  const exists = db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase());
  if (exists) return res.status(409).json({error:'Email đã tồn tại'});
  const hash = bcrypt.hashSync(password, 12);
  const info = db.prepare('INSERT INTO users(name,email,password_hash,balance,role) VALUES(?,?,?,0,?)').run(name.trim(), email.toLowerCase(), hash, 'customer');
  const user = db.prepare('SELECT id,name,email,balance,role FROM users WHERE id=?').get(info.lastInsertRowid);
  res.json({ token: tokenFor(user), user });
});

app.post('/api/login', (req,res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email=?').get((email||'').toLowerCase());
  if (!user || !bcrypt.compareSync(password||'', user.password_hash)) return res.status(401).json({error:'Sai email hoặc mật khẩu'});
  res.json({ token: tokenFor(user), user: {id:user.id,name:user.name,email:user.email,balance:user.balance,role:user.role} });
});

app.post('/api/admin/login', (req,res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USER || password !== ADMIN_PASS) return res.status(401).json({error:'Sai tài khoản admin'});
  const user = { id: 0, email: 'admin', role: 'admin' };
  res.json({ token: tokenFor(user) });
});

app.get('/api/me', auth, (req,res) => {
  if (req.user.role === 'admin') return res.json({user:{id:0,name:'Admin',email:'admin',balance:0,role:'admin'}});
  const user = db.prepare('SELECT id,name,email,balance,role FROM users WHERE id=?').get(req.user.id);
  res.json({user});
});

app.get('/api/products', (req,res) => res.json({ products: db.prepare('SELECT * FROM products WHERE active=1 ORDER BY id DESC').all() }));

app.post('/api/topups', auth, (req,res) => {
  if (req.user.role === 'admin') return res.status(400).json({error:'Không hợp lệ'});
  const amount = money(req.body.amount);
  if (!Number.isInteger(amount) || amount < 10000) return res.status(400).json({error:'Nạp tối thiểu 10.000đ'});
  const code = 'NAP-' + crypto.randomBytes(5).toString('hex').toUpperCase();
  const tx = db.prepare('INSERT INTO transactions(user_id,type,amount,status,code) VALUES(?,?,?,?,?)').run(req.user.id,'topup',amount,'pending',code);
  res.json({ id: tx.lastInsertRowid, code, amount, bank: getBank(), qr: makeQr(getBank(), amount, code) });
});

function getBank(){ return db.prepare('SELECT * FROM bank_settings WHERE id=1').get(); }
function makeQr(bank, amount, code){
  if (bank.qr_url) return bank.qr_url;
  return `https://img.vietqr.io/image/970407-${encodeURIComponent(bank.account_number)}-compact2.png?amount=${amount}&addInfo=${encodeURIComponent(code)}&accountName=${encodeURIComponent(bank.owner)}`;
}

app.get('/api/bank', (req,res)=>{ const b=getBank(); res.json({bank:b, qr:makeQr(b,0,'')}); });

app.get('/api/my-transactions', auth, (req,res) => {
  const rows = db.prepare('SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC').all(req.user.id);
  res.json({transactions:rows});
});

app.post('/api/purchases', auth, (req,res) => {
  const product = db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(req.body.productId);
  if (!product) return res.status(404).json({error:'Không tìm thấy sản phẩm'});
  const qty = Math.max(1, parseInt(req.body.quantity || 1, 10));
  const total = product.price * qty;
  const tx = db.transaction(() => {
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    if (user.balance < total) throw new Error('Số dư không đủ');
    db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(total, req.user.id);
    const info = db.prepare('INSERT INTO transactions(user_id,type,amount,status,product_id,quantity) VALUES(?,?,?,?,?,?)').run(req.user.id,'purchase',total,'completed',product.id,qty);
    db.prepare('INSERT INTO orders(user_id,product_id,quantity,total,transaction_id,status) VALUES(?,?,?,?,?,?)').run(req.user.id,product.id,qty,total,info.lastInsertRowid,'paid');
    return info.lastInsertRowid;
  });
  try { res.json({ok:true,transactionId:tx}); } catch(e) { res.status(400).json({error:e.message}); }
});

app.get('/api/orders', auth, (req,res) => {
  const rows = db.prepare(`SELECT o.*, p.name product_name FROM orders o JOIN products p ON p.id=o.product_id WHERE o.user_id=? ORDER BY o.id DESC`).all(req.user.id);
  res.json({orders:rows});
});

app.get('/api/orders/:id/delivery', auth, (req,res) => {
  const o = db.prepare('SELECT * FROM orders WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!o) return res.status(404).json({error:'Không tìm thấy đơn'});
  const items = db.prepare('SELECT id,text,file_name,file_url FROM deliveries WHERE order_id=? ORDER BY id DESC').all(o.id);
  res.json({items});
});

// Admin APIs
app.get('/api/admin/overview', auth, admin, (req,res)=>{
  res.json({users:db.prepare('SELECT id,name,email,balance,created_at FROM users ORDER BY id DESC').all(), transactions:db.prepare(`SELECT t.*,u.email FROM transactions t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC`).all(), orders:db.prepare(`SELECT o.*,u.email,p.name product_name FROM orders o JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id ORDER BY o.id DESC`).all(), products:db.prepare('SELECT * FROM products ORDER BY id DESC').all(), bank:getBank()});
});
app.post('/api/admin/products', auth, admin, (req,res)=>{ const {name,price,description=''}=req.body; const r=db.prepare('INSERT INTO products(name,price,description,active) VALUES(?,?,?,1)').run(name,Number(price),description); res.json({id:r.lastInsertRowid}); });
app.delete('/api/admin/products/:id', auth, admin, (req,res)=>{ db.prepare('UPDATE products SET active=0 WHERE id=?').run(req.params.id); res.json({ok:true}); });
app.post('/api/admin/topups/:id/approve', auth, admin, (req,res)=>{ const tx=db.prepare('SELECT * FROM transactions WHERE id=?').get(req.params.id); if(!tx||tx.type!=='topup'||tx.status!=='pending') return res.status(400).json({error:'Giao dịch không hợp lệ'}); const run=db.transaction(()=>{db.prepare('UPDATE transactions SET status=\'approved\' WHERE id=?').run(tx.id); db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(tx.amount,tx.user_id);}); run(); res.json({ok:true}); });
app.post('/api/admin/topups/:id/reject', auth, admin, (req,res)=>{ db.prepare("UPDATE transactions SET status='rejected' WHERE id=? AND type='topup' AND status='pending'").run(req.params.id); res.json({ok:true}); });
app.post('/api/admin/orders/:id/delivery', auth, admin, upload.single('file'), (req,res)=>{ const o=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id); if(!o) return res.status(404).json({error:'Không tìm thấy đơn'}); const fileUrl=req.file?`/uploads/${req.file.filename}`:null; db.prepare('INSERT INTO deliveries(order_id,text,file_name,file_url) VALUES(?,?,?,?)').run(o.id,req.body.text||'',req.file?.originalname||null,fileUrl); db.prepare("UPDATE orders SET status='delivered' WHERE id=?").run(o.id); res.json({ok:true}); });
app.put('/api/admin/bank', auth, admin, (req,res)=>{ const {bank,owner,account_number,qr_url=''}=req.body; db.prepare('UPDATE bank_settings SET bank=?,owner=?,account_number=?,qr_url=? WHERE id=1').run(bank,owner,account_number,qr_url); res.json({ok:true}); });

app.get('/', (req,res)=>res.sendFile(path.join(root,'shop.html')));
app.get('/admin', (req,res)=>res.sendFile(path.join(root,'admin.html')));
app.listen(PORT,()=>console.log(`Shop running: http://localhost:${PORT}`));
