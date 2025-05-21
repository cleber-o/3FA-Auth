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

// Carregar e salvar JSON
function loadDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
}
function saveDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// Gerar hash da senha
function scryptHash(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

// Descobre a localização do usuário com base no IP
async function getUserLocation(ip) {
  try {
    const res = await fetch(`https://ipinfo.io/${ip}?token=86de7225565d9a`);
    const data = await res.json();
    return data.country || "??";
  } catch (err) {
    console.error("Erro ao obter IPInfo:", err);
    return "??";
  }
}

// Cadastro de usuário
app.post("/register", async (req, res) => {
  const { username, password, phone, ip } = req.body;
  const db = loadDB();
  const userExists = db.users.some((u) => u.username === username);
  if (userExists) {
    return res.status(400).json({ message: "Usuário já existe" });
  }

  const location = await getUserLocation(ip);
  const passwordSalt = crypto.randomBytes(16); // Gera um salt aleatório para a senha
  const totpSalt = crypto.randomBytes(16); // Gera um salt aleatório para o TOTP

  const hashedPassword = scryptHash(password, passwordSalt); // Hash da senha

  const otpSecret = new OTPAuth.Secret(); // generates random secret

  const secretBase32 = otpSecret.base32; 

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
  };

  db.users.push(newUser);
  saveDB(db);

  res.json({
    message: "Usuário cadastrado com sucesso!",
    qrUri: otpauth,
  });
});

// Login
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

  // Verfica se o token gerado é igual ao token recebido
  const isValid = totpVerifier.validate({ token: totp.toString(), window: 1 });
  if (isValid === null) {
    return res.status(401).json({ message: "Código TOTP inválido." });
  }
  res.json({ message: "Login realizado com sucesso." });
});

// Mensagem cifrada
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
    const ivBuf = Buffer.from(iv, "hex");
    const authTagBuf = Buffer.from(authTag, "hex");
    const ciphertextBuf = Buffer.from(message, "hex");

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, ivBuf);
    decipher.setAuthTag(authTagBuf);

    const decrypted = Buffer.concat([
      decipher.update(ciphertextBuf),
      decipher.final(),
    ]);

    console.log("mensagem cifrada:", message);
    console.log("mensagem clara:", decrypted.toString("utf8"));

    res.json({ message: "Mensagem recebida e decifrada com sucesso!" });
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

// Ligar a porta 3000
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

// Prints no console
const originalConsoleError = console.error;
console.error = function () {
  const args = Array.from(arguments);
  return originalConsoleError.apply(console, args);
};
