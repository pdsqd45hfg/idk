require('dotenv').config();
const express = require('express');
const Discord = require('discord.js');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');

// إعداد التطبيق
const app = express();
const PORT = process.env.PORT || 3000;

// الاتصال بقاعدة البيانات
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/botek', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// نماذج البيانات
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  themePreference: { type: String, default: 'dark' },
  createdAt: { type: Date, default: Date.now }
});

const botSchema = new mongoose.Schema({
  name: { type: String, required: true },
  token: { type: String, required: true },
  type: { type: String, enum: ['music', 'moderation', 'fun', 'utility'], required: true },
  status: { type: String, default: 'offline' },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Bot = mongoose.model('Bot', botSchema);

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// حماية ضد السبام
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// تخزين البوتات المفعلة
const activeBots = new Map();

async function startBot(botData) {
  try {
    const client = new Discord.Client({
      intents: [
        Discord.GatewayIntentBits.Guilds,
        Discord.GatewayIntentBits.GuildMessages,
        Discord.GatewayIntentBits.MessageContent,
        Discord.GatewayIntentBits.GuildVoiceStates
      ]
    });

    client.on('ready', () => {
      console.log(`🤖 Bot ${botData.name} is ready!`);
      activeBots.set(botData._id.toString(), client);
      Bot.findByIdAndUpdate(botData._id, { status: 'online' }).exec();
    });

    client.on('error', error => {
      console.error(`❌ Bot ${botData.name} error:`, error);
      Bot.findByIdAndUpdate(botData._id, { status: 'error' }).exec();
    });

    await client.login(botData.token);
    return true;
  } catch (error) {
    console.error(`❌ Failed to start bot ${botData.name}:`, error.message);
    return false;
  }
}

// 🧠 API Endpoints

// تسجيل مستخدم جديد
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, themePreference } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, themePreference });
    await user.save();
    res.status(201).json({ message: '✅ User created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// تسجيل الدخول
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    res.json({ token, themePreference: user.themePreference });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// تحديث ثيم المستخدم
app.post('/api/update-theme', async (req, res) => {
  try {
    const { themePreference } = req.body;
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');

    await User.findByIdAndUpdate(decoded.userId, { themePreference });
    res.json({ message: '✅ Theme updated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// إنشاء بوت جديد
app.post('/api/bots', async (req, res) => {
  try {
    const { name, token, type } = req.body;
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    const tokenParts = authHeader.split(' ');
    const decoded = jwt.verify(tokenParts[1], process.env.JWT_SECRET || 'secret');

    const bot = new Bot({ name, token, type, owner: decoded.userId });
    await bot.save();

    const started = await startBot(bot);
    if (!started) return res.status(400).json({ error: '❌ Failed to start bot' });

    res.status(201).json(bot);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// عرض البوتات الخاصة بالمستخدم
app.get('/api/bots', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const tokenParts = authHeader.split(' ');
    const decoded = jwt.verify(tokenParts[1], process.env.JWT_SECRET || 'secret');

    const bots = await Bot.find({ owner: decoded.userId });
    res.json(bots);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// التعامل مع مسارات API الغير موجودة
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: '❌ API endpoint not found' });
});

// التعامل مع الواجهة
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// بدء السيرفر
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
