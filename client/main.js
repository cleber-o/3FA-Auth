// Detecta qual página está aberta
document.addEventListener("DOMContentLoaded", async () => {
  const path = window.location.pathname;

  // Captura IP público
  async function getPublicIP() {
    try {
      const res = await fetch("https://api.ipify.org?format=json");
      const data = await res.json();
      return data.ip;
    } catch {
      return null;
    }
  }

  // Cadastro de usuário
  if (path.includes("cadastro.html")) {
    const form = document.getElementById("registerForm");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();

      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;
      const phone = document.getElementById("phone").value;
      const ip = await getPublicIP();

      const user = { username, password, phone, ip };

      try {
        const res = await fetch("http://localhost:3000/register", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(user),
        });

        const result = await res.json();
        document.getElementById("status").innerText = result.message;

        if (result.qrUri) {
          const qrContainer = document.getElementById("qrcode");

          // Limpa espaços e caracteres ocultos
          const cleanUri = result.qrUri.trim();

          if (qrContainer) {
            QRCode.toDataURL(cleanUri, function (error, url) {
              if (error) {
                console.error("Erro ao gerar QRCode:", error.message);
                return;
              }

              const img = document.createElement("img");
              img.src = url;
              img.alt = "QR Code";
              img.style.marginTop = "20px";

              qrContainer.innerHTML = ""; // limpa qualquer conteúdo anterior
              qrContainer.appendChild(img);
            });
          } else {
            console.warn("Elemento #qrcode não encontrado no HTML.");
          }
        } else {
          console.warn("QR URI inválida ou ausente:", result.qrUri);
        }
      } catch (err) {
        console.error(err);
        document.getElementById("status").innerText = err.message;
      }
    });
  }

  // Login de usuário
  if (path.includes("login.html")) {
    const form = document.getElementById("loginForm");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();

      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;
      const totp = document.getElementById("totp").value;
      const ip = await getPublicIP();

      const user = { username, password, totp, ip };

      try {
        const res = await fetch("http://localhost:3000/auth", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(user),
        });

        const result = await res.json();
        document.getElementById("status").innerText = result.message;

        if (res.ok) {
          // Derivar chave simétrica com o TOTP e salvar no localStorage
          const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(totp),
            "PBKDF2",
            false,
            ["deriveKey"]
          );

          const saltRes = await fetch("http://localhost:3000/get-user-salt", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ username }),
          });

          const { totpSalt } = await saltRes.json();

          const key = await window.crypto.subtle.deriveKey(
            {
              name: "PBKDF2",
              salt: Uint8Array.from(atob(totpSalt), (c) => c.charCodeAt(0)),
              iterations: 100000,
              hash: "SHA-256",
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
          );

          const exportedKey = await window.crypto.subtle.exportKey("raw", key);
          const keyHex = Array.from(new Uint8Array(exportedKey))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");

          localStorage.setItem("loggedInUser", username);
          localStorage.setItem("symmetricKey", keyHex);

          window.location.href = "mensagem.html";
        }
      } catch (err) {
        console.error(err);
        document.getElementById("status").innerText = "Erro ao autenticar.";
      }
    });
  }

  // Tela de mensagens
  if (path.includes("mensagem.html")) {
    const loggedUser = localStorage.getItem("loggedInUser");

    if (!loggedUser) {
      alert("Você precisa estar logado para acessar essa página.");
      window.location.href = "login.html";
      return;
    }

    const form = document.getElementById("messageForm");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();

      const message = document.getElementById("message").value;
      const keyHex = localStorage.getItem("symmetricKey");

      if (!keyHex) {
        alert("Chave não encontrada. Faça login novamente.");
        window.location.href = "login.html";
        return;
      }

      const keyBytes = new Uint8Array(
        keyHex.match(/.{1,2}/g).map((b) => parseInt(b, 16))
      );
      const key = await window.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );

      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encodedMsg = new TextEncoder().encode(message);
      const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encodedMsg
      );

      const encryptedBytes = new Uint8Array(encrypted);
      const ciphertextBytes = encryptedBytes.slice(0, -16);
      const authTagBytes = encryptedBytes.slice(-16);

      const encryptedHex = Array.from(ciphertextBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const authTag = Array.from(authTagBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const ivHex = Array.from(iv)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      const payload = {
        username: loggedUser,
        message: encryptedHex,
        iv: ivHex,
        authTag,
      };

      try {
        const res = await fetch("http://localhost:3000/message", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        });

        const result = await res.json();
        document.getElementById("status").innerText = result.message;
      } catch (err) {
        console.error(err);
        document.getElementById("status").innerText =
          "Erro ao enviar mensagem.";
      }
    });
  }
});
