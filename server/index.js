import express from "express";
import cors from "cors";
import fs from "fs";
import crypto from "crypto";
import fetch from "node-fetch";
import * as OTPAuth from "otpauth";

const app = express();
const PORT = 3000;
app.use(cors());
app.use(express.json());

const DB_PATH = "./server/database.json";

// Carregar e salvar JSON
function loadDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
}
function saveDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// Gera salt base64
function generateSalt() {
  return crypto.randomBytes(16).toString("base64");
}

// Gera hash de senha (Scrypt)
function deriveScryptKey(password, saltBase64) {
  const salt = Buffer.from(saltBase64, "base64");
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

// Deriva chave para TOTP/Message com PBKDF2
function derivePBKDF2Key(input, saltBase64) {
  const salt = Buffer.from(saltBase64, "base64");
  // 256 bits de chave AES
  return crypto.pbkdf2Sync(input, salt, 100000, 32, "sha256");
}

// Valida TOTP usando otpauth
function validateTOTP(secret, token) {
  const totp = new OTPAuth.TOTP({
    secret: OTPAuth.Secret.fromBase32(secret),
    digits: 6,
    period: 30,
    algorithm: "SHA1",
  });
  return totp.validate({ token: token.toString(), window: 1 }) !== null;
}

// Descobre a localização do usuário com base no IP
async function getUserLocation(ip) {
  try {
    const res = await fetch(`https://ipinfo.io/${ip}?token=86de7225565d9a`);
    const data = await res.json();
    return data.country || null;
  } catch (err) {
    console.error("Erro ao obter IPInfo:", err);
    return "??";
  }
}

// Decifra com AES-GCM
function decipherGcm(encryptedHex, key, ivHex, authTagHex) {
  const ciphertext = Buffer.from(encryptedHex, "hex");
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}

// Cadastro de usuário
app.post("/register", async (req, res) => {
  const { username, password, phone, ip } = req.body;
  const db = loadDB();
  if (db.users.some((u) => u.username === username)) {
    return res.status(400).json({ message: "Usuário já existe" });
  }

  const location = await getUserLocation(ip);
  const passwordSalt = crypto.randomBytes(16); // Gera um salt aleatório para a senha
  const totpSalt = crypto.randomBytes(16); // Gera um salt aleatório para o TOTP

  const hashedPassword = deriveScryptKey(password, passwordSalt); // Hash da senha

  const otpSecret = new OTPAuth.Secret(); // generates random secret

  const secretBase32 = otpSecret.base32;
  const messageSalt = generateSalt();

  // Gera o URI do TOTP
  const totp = new OTPAuth.TOTP({
    issuer: "3FA-Auth-App",
    label: username,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: otpSecret,
  });

  const otpauth = totp.toString();

  const newUser = {
    username,
    password: hashedPassword,
    location,
    phone,
    passwordSalt: passwordSalt.toString("base64"),
    totpSalt: totpSalt.toString("base64"),
    secret: secretBase32,
    messageSalt,
  };

  db.users.push(newUser);
  saveDB(db);

  res.json({
    message: "Usuário cadastrado com sucesso!",
    qrUri: otpauth,
  });
});

// Autenticação
app.post("/auth", async (req, res) => {
  const {
    username,
    password,
    totp,
    location: locationFromClient,
    ip,
  } = req.body;

  const db = loadDB();
  const user = db.users.find((u) => u.username === username);

  if (!user) {
    return res.status(401).json({ message: "Usuário não encontrado!" });
  }

  // Verifica localização
  const location = await getUserLocation(ip);
  if (user.location !== location) {
    return res.status(401).json({ message: "Localização inválida!" });
  }

  // Valida senha
  const encryptedPassword = deriveScryptKey(password, user.passwordSalt);
  if (encryptedPassword !== user.password) {
    return res.status(401).json({ message: "Senha incorreta!" });
  }

  // Valida TOTP
  const isTokenValid = validateTOTP(user.secret, totp);
  if (!isTokenValid) {
    return res.status(401).json({ message: "Token TOTP inválido!" });
  }

  // Salva o TOTP da sessão temporariamente (apenas em disco)
  user.sessionTotp = totp;
  saveDB(db);

  res.status(200).json({
    message: "Usuário autenticado com sucesso!",
    messageSalt: user.messageSalt,
  });
});

// Mensagem cifrada
app.post("/message", (req, res) => {
  const { username, ciphertext, authTag, iv } = req.body;

  const db = loadDB();
  const user = db.users.find((u) => u.username === username);

  if (!user || !user.sessionTotp) {
    return res.status(401).json({ message: "Faça login novamente!" });
  }

  // Deriva a chave de mensagem a partir do TOTP da sessão
  const key = derivePBKDF2Key(user.sessionTotp, user.messageSalt);

  try {
    const msgDecifrada = decipherGcm(ciphertext, key, iv, authTag);

    console.log("Mensagem decifrada:", msgDecifrada);

    res.status(200).json({ message: "Mensagem recebida com sucesso!" });
  } catch (err) {
    console.error("Erro ao decifrar a mensagem:", err.message);
    res.status(400).json({ message: "Falha ao decifrar a mensagem." });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

// Prints no console
const originalConsoleError = console.error;
console.error = function () {
  const args = Array.from(arguments);
  return originalConsoleError.apply(console, args);
};
