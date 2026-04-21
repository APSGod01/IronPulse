import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { createServer as createViteServer } from 'vite';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import path from 'path';
import multer from 'multer';
import Stripe from 'stripe';
import db from './src/db.ts';

const JWT_SECRET = process.env.JWT_SECRET || 'gym-secret-key';
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

// Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

async function startServer() {
  const app = express();
  const httpServer = createServer(app);
  const io = new Server(httpServer, {
    cors: { origin: '*' }
  });

  app.use(cors());
  app.use(express.json());

  // Auth Middleware
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      next();
    } catch {
      res.status(401).json({ error: 'Invalid token' });
    }
  };

  // API Routes
  app.post('/api/auth/register', async (req, res) => {
    const { email, password, name, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const referralCode = Math.random().toString(36).substring(7).toUpperCase();
    
    try {
      const result = db.prepare('INSERT INTO users (email, password, name, role, referral_code) VALUES (?, ?, ?, ?, ?)')
        .run(email, hashedPassword, name, role || 'member');
      res.json({ id: result.lastInsertRowid });
    } catch (e) {
      res.status(400).json({ error: 'Email already exists' });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as any;
    
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET);
      res.json({ token, user: { id: user.id, name: user.name, role: user.role, email: user.email } });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });

  app.get('/api/me', authenticate, (req: any, res) => {
    const user = db.prepare('SELECT id, email, name, role, membership_tier, credits, referral_code FROM users WHERE id = ?').get(req.user.id);
    res.json(user);
  });

  // Attendance
  app.post('/api/attendance/checkin', authenticate, (req: any, res) => {
    db.prepare('INSERT INTO attendance (user_id) VALUES (?)').run(req.user.id);
    io.emit('notification', { message: `${req.user.name} just checked in!`, type: 'checkin' });
    res.json({ success: true });
  });

  app.get('/api/attendance/stats', authenticate, (req: any, res) => {
    const stats = db.prepare('SELECT COUNT(*) as count, DATE(check_in_time) as date FROM attendance GROUP BY DATE(check_in_time) ORDER BY date DESC LIMIT 7').all();
    res.json(stats);
  });

  // Workouts
  app.get('/api/workouts', authenticate, (req: any, res) => {
    const workouts = db.prepare('SELECT * FROM workouts WHERE user_id = ? ORDER BY date DESC').all(req.user.id);
    res.json(workouts);
  });

  app.post('/api/workouts', authenticate, (req: any, res) => {
    const { exercise, weight, reps, sets } = req.body;
    db.prepare('INSERT INTO workouts (user_id, exercise, weight, reps, sets) VALUES (?, ?, ?, ?, ?)')
      .run(req.user.id, exercise, weight, reps, sets);
    res.json({ success: true });
  });

  // Classes
  app.get('/api/classes', (req, res) => {
    const classes = db.prepare(`
      SELECT c.*, u.name as trainer_name, 
      (SELECT COUNT(*) FROM bookings b WHERE b.class_id = c.id) as current_bookings
      FROM classes c
      JOIN users u ON c.trainer_id = u.id
    `).all();
    res.json(classes);
  });

  app.post('/api/classes/book', authenticate, (req: any, res) => {
    const { classId } = req.body;
    db.prepare('INSERT INTO bookings (user_id, class_id) VALUES (?, ?)').run(req.user.id, classId);
    res.json({ success: true });
  });

  // Social Feed
  app.get('/api/social', (req, res) => {
    const posts = db.prepare(`
      SELECT p.*, u.name as user_name 
      FROM social_posts p 
      JOIN users u ON p.user_id = u.id 
      ORDER BY p.created_at DESC
    `).all();
    res.json(posts);
  });

  app.post('/api/social', authenticate, (req: any, res) => {
    const { content, imageUrl } = req.body;
    db.prepare('INSERT INTO social_posts (user_id, content, image_url) VALUES (?, ?, ?)')
      .run(req.user.id, content, imageUrl);
    res.json({ success: true });
  });

  // Leaderboard
  app.get('/api/leaderboard', (req, res) => {
    const leaders = db.prepare(`
      SELECT u.id, u.name, 
      ( (SELECT COUNT(*) FROM attendance a WHERE a.user_id = u.id) * 10 + 
        (SELECT COUNT(*) FROM workouts w WHERE w.user_id = u.id) * 5 ) as score
      FROM users u
      WHERE u.role = 'member'
      ORDER BY score DESC
      LIMIT 10
    `).all();
    res.json(leaders);
  });

  // Stripe Payments
  app.post('/api/payments/create-checkout', authenticate, async (req: any, res) => {
    if (!stripe) {
      return res.status(500).json({ error: 'Stripe is not configured' });
    }
    const { tier, price } = req.body;
    
    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: { name: `IronPulse ${tier} Membership` },
            unit_amount: price * 100,
          },
          quantity: 1,
        }],
        mode: 'payment',
        success_url: `${process.env.APP_URL}/?payment=success`,
        cancel_url: `${process.env.APP_URL}/?payment=cancel`,
        customer_email: req.user.email,
        metadata: { userId: req.user.id, tier }
      });
      res.json({ url: session.url });
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  // File Uploads (Waivers/Photos)
  app.post('/api/upload', authenticate, upload.single('file'), (req: any, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ url: `/uploads/${req.file.filename}` });
  });

  // Seed Data (for demo)
  app.post('/api/admin/seed', authenticate, (req: any, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    
    // Add some trainers if they don't exist
    const trainers = [
      { email: 'trainer1@gym.com', name: 'Alex Johnson', role: 'trainer' },
      { email: 'trainer2@gym.com', name: 'Sarah Smith', role: 'trainer' }
    ];

    trainers.forEach(t => {
      try {
        db.prepare('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)')
          .run(t.email, 'password123', t.name, t.role);
      } catch (e) {}
    });

    // Add some classes
    const classData = [
      { name: 'Morning Yoga', trainer_id: 2, start_time: '2026-03-14 08:00:00', capacity: 20, type: 'Yoga' },
      { name: 'HIIT Blast', trainer_id: 3, start_time: '2026-03-14 10:00:00', capacity: 15, type: 'CrossFit' }
    ];

    classData.forEach(c => {
      db.prepare('INSERT INTO classes (name, trainer_id, start_time, capacity, type) VALUES (?, ?, ?, ?, ?)')
        .run(c.name, c.trainer_id, c.start_time, c.capacity, c.type);
    });

    res.json({ success: true });
  });

  // Vite Integration
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(process.cwd(), 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(process.cwd(), 'dist', 'index.html'));
    });
  }

  const PORT = 3000;
  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
    
    // Auto-seed if empty
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get() as any;
    if (userCount.count === 0) {
      console.log('Seeding initial data...');
      const hashedPassword = bcrypt.hashSync('admin123', 10);
      db.prepare('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)')
        .run('admin@gym.com', hashedPassword, 'Admin User', 'admin');
      
      const trainers = [
        { email: 'trainer1@gym.com', name: 'Alex Johnson', role: 'trainer' },
        { email: 'trainer2@gym.com', name: 'Sarah Smith', role: 'trainer' }
      ];
      trainers.forEach(t => {
        db.prepare('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)')
          .run(t.email, bcrypt.hashSync('trainer123', 10), t.name, t.role);
      });

      // Add some members
      const members = [
        { email: 'member1@gym.com', name: 'John Doe', role: 'member' },
        { email: 'member2@gym.com', name: 'Jane Doe', role: 'member' }
      ];
      members.forEach(m => {
        db.prepare('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)')
          .run(m.email, bcrypt.hashSync('member123', 10), m.name, m.role);
      });
      
      // Add some classes
      const classData = [
        { name: 'Morning Yoga', trainer_id: 2, start_time: '2026-03-14 08:00:00', capacity: 20, type: 'Yoga' },
        { name: 'HIIT Blast', trainer_id: 3, start_time: '2026-03-14 10:00:00', capacity: 15, type: 'CrossFit' },
        { name: 'Zumba Party', trainer_id: 2, start_time: '2026-03-15 18:00:00', capacity: 30, type: 'Zumba' }
      ];

      classData.forEach(c => {
        db.prepare('INSERT INTO classes (name, trainer_id, start_time, capacity, type) VALUES (?, ?, ?, ?, ?)')
          .run(c.name, c.trainer_id, c.start_time, c.capacity, c.type);
      });

      // Add some initial social posts
      db.prepare('INSERT INTO social_posts (user_id, content) VALUES (?, ?)')
        .run(4, 'Just finished my first HIIT class! Feeling amazing! 🚀');
      db.prepare('INSERT INTO social_posts (user_id, content) VALUES (?, ?)')
        .run(5, 'Yoga this morning was exactly what I needed. Namaste. 🙏');

      console.log('Seed complete. Admin: admin@gym.com / admin123');
    }
  });

  io.on('connection', (socket) => {
    console.log('Client connected');
  });
}

startServer();
