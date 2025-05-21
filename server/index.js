

import express from 'express';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import fetch from 'node-fetch';
import { authenticator } from 'otplib';

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const DB_PATH = './server/database.json';
const IPINFO_TOKEN = process.env.IPINFO_TOKEN;

function loadDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 32);
}

function getCountryByIP(ip) {
  return fetch(`https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`)
    .then(res => res.json())
    .then(data => data.country || '')
    .catch(() => '');
}

app.post('/auth', async (req, res) => {
  const { username, password, totp, message } = req.body;
  const userIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  const db = loadDB();
  const user = db.users?.find(u => u.username === username);

  if (!user) return res.status(401).json({ message: 'Usuário não encontrado' });

  // 1. Verificar país por IP
  const userCountry = await getCountryByIP(userIP);
  if (userCountry !== user.country) {
    return res.status(401).json({ message: 'IP fora da região esperada' });
  }

  // 2. Verificar senha
  const derivedKey = hashPassword(password, Buffer.from(user.salt, 'hex'));
  const storedKey = Buffer.from(user.hashedPassword, 'hex');
  if (!crypto.timingSafeEqual(derivedKey, storedKey)) {
    return res.status(401).json({ message: 'Senha incorreta' });
  }

  // 3. Verificar TOTP
  if (!authenticator.check(totp, user.secret)) {
    return res.status(401).json({ message: 'Código TOTP inválido' });
  }

  // Derivar chave simétrica da TOTP e salt
  const key = crypto.scryptSync(totp, Buffer.from(user.salt, 'hex'), 32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(message, 'utf-8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  res.json({
    message: 'Autenticação bem-sucedida!',
    encryptedMessage: encrypted,
    iv: iv.toString('hex'),
    authTag
  });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});