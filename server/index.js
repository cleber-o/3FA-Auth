import express from "express";
import cors from "cors";
import fs from "fs";
import crypto from "crypto";
import fetch from "node-fetch";
import { generateSecret, generateKeyUri } from "../utils/totp.js";
import * as OTPAuth from "otpauth";

const app = express();
const PORT = 3000;
app.use(cors());
app.use(express.json());

const DB_PATH = "./server/database.json";
const IPINFO_TOKEN = process.env.IPINFO_TOKEN;

// Função utilitária para carregar e salvar JSON
function loadDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
}

function saveDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

function scryptHash(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

async function getUserLocation(ip) {
  try {
    const res = await fetch(`https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`);
    const data = await res.json();
    return data.country || "??";
  } catch (err) {
    console.error("Erro ao obter IPInfo:", err);
    return "??";
  }
}

// registra um novo usuário
app.post("/register", async (req, res) => {
  const { username, password, phone, ip } = req.body;
  const db = loadDB();
  const userExists = db.users.some((u) => u.username === username);
  if (userExists) {
    return res.status(400).json({ message: "Usuário já existe" });
  }

  const location = await getUserLocation(ip);
  const passwordSalt = crypto.randomBytes(16);
  const totpSalt = crypto.randomBytes(16); // se quiser usar na derivação

  const hashedPassword = scryptHash(password, passwordSalt);

  const otpSecret = new OTPAuth.Secret(); // generates random secret
  const secretBase32 = otpSecret.base32;
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
  };

  db.users.push(newUser);
  saveDB(db);

  res.json({
    message: "Usuário cadastrado com sucesso!",
    qrUri: otpauth,
  });
});

// Rota de login
app.post("/auth", async (req, res) => {
  const { username, password, totp, ip } = req.body;

  const db = loadDB();
  const user = db.users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ message: "Usuário não encontrado." });
  }

  // Verifica IP (localização)
  const userLocation = await getUserLocation(ip);
  if (userLocation !== user.location) {
    return res
      .status(403)
      .json({ message: "IP fora da localização permitida." });
  }

  // Verifica senha
  const saltBuffer = Buffer.from(user.passwordSalt, "base64");
  const hashedInput = crypto
    .scryptSync(password, saltBuffer, 64)
    .toString("hex");
  if (hashedInput !== user.password) {
    return res.status(401).json({ message: "Senha incorreta." });
  }

  // Verifica TOTP
  const secret = OTPAuth.Secret.fromBase32(user.secret);
  const totpVerifier = new OTPAuth.TOTP({
    issuer: "3FA-Auth-App",
    label: username,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: secret,
  });

  const currentToken = totpVerifier.generate();
  console.log("Token esperado agora:", currentToken);
  console.log("Token recebido:", totp);

  // const isValid = totpVerifier.validate({ token: totp, window: 1 });
  const isValid = totpVerifier.validate({ token: totp.toString(), window: 1 });
  if (isValid === null) {
    return res.status(401).json({ message: "Código TOTP inválido." });
  }

  res.json({ message: "Login realizado com sucesso." });
});

// Rota para submissão de mensagens cifradas
app.post("/message", async (req, res) => {
  const { username, message, iv, authTag } = req.body;

  const db = loadDB();
  const user = db.users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ message: "Usuário não encontrado." });
  }

  // Simula o armazenamento da symmetricKey após login, caso não exista
  if (!user.symmetricKey) {
    // Gera uma chave simétrica aleatória de 32 bytes (256 bits)
    user.symmetricKey = crypto.randomBytes(32).toString("hex");
    saveDB(db);
  }
  const key = Buffer.from(user.symmetricKey, "hex");

  try {
    // const ivBuf = Buffer.from(iv, "hex");
    // const authTagBuf = Buffer.from(authTag, "hex");
    // const ciphertextBuf = Buffer.from(message, "hex");

    // console.log("iv:", ivBuf);
    // console.log("authTagBuf:", authTagBuf);
    // console.log("ciphertextBuf:", ciphertextBuf);

    // const decipher = crypto.createDecipheriv("aes-256-gcm", key, ivBuf);
    // decipher.setAuthTag(authTagBuf);

    // const decrypted = Buffer.concat([
    //   decipher.update(ciphertextBuf),
    //   decipher.final(),
    // ]);

    // console.log("mensagem cifrada:");
    // console.log("mensagem clara:");

    // res.json({ message: "Mensagem recebida e decifrada com sucesso!" });
  } catch (err) {
    console.error("Erro ao decifrar a mensagem:", err.message);
    res.status(400).json({ message: "Falha ao decifrar a mensagem." });
  }
});

app.post("/get-user-salt", (req, res) => {
  const { username } = req.body;
  const db = loadDB();
  const user = db.users.find((u) => u.username === username);

  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado." });
  }

  res.json({ totpSalt: user.totpSalt });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

const originalConsoleError = console.error;

const redColor = "\x1b[31m";
const resetColor = "\x1b[0m";

console.error = function () {
  const args = Array.from(arguments);

  if (typeof args[0] === "string") {
    args[0] = redColor + args[0];
  } else {
    args.unshift(redColor);
  }

  args.push(resetColor);

  return originalConsoleError.apply(console, args);
};
