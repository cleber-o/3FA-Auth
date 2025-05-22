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

  // Login
  if (path.includes("login.html")) {
    document
      .getElementById("loginForm")
      .addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;
        const totp = document.getElementById("totp").value;
        const ip = await getPublicIP();

        const res = await fetch("http://localhost:3000/auth", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password, totp, ip }),
        });
        const result = await res.json();
        document.getElementById("status").innerText = result.message;

        if (res.ok && result.messageSalt) {
          localStorage.setItem("loggedInUser", username);
          localStorage.setItem("messageSalt", result.messageSalt);
          window.location.href = "mensagem.html";
        }
      });
  }

  // Envio de Mensagem
  if (path.includes("mensagem.html")) {
    const username = localStorage.getItem("loggedInUser");
    const messageSalt = localStorage.getItem("messageSalt");

    if (!username || !messageSalt) {
      alert("Faça login novamente.");
      window.location.href = "login.html";
      return;
    }

    document
      .getElementById("messageForm")
      .addEventListener("submit", async (e) => {
        e.preventDefault();

        // 1. Solicite TOTP via prompt
        const totp = prompt("Digite seu código TOTP atual:");

        // 2. Derive chave simétrica PBKDF2 (256 bits)
        const keyMaterial = await window.crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(totp),
          "PBKDF2",
          false,
          ["deriveKey"]
        );
        const key = await window.crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: Uint8Array.from(atob(messageSalt), (c) => c.charCodeAt(0)),
            iterations: 100000,
            hash: "SHA-256",
          },
          keyMaterial,
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"]
        );

        // 3. Gere IV aleatório
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // 4. Cifre a mensagem
        const msg = new TextEncoder().encode(
          document.getElementById("message").value
        );
        const encrypted = await window.crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          key,
          msg
        );

        const encryptedBytes = new Uint8Array(encrypted);
        const ciphertextBytes = encryptedBytes.slice(0, -16);
        const authTagBytes = encryptedBytes.slice(-16);

        // 5. Envie para o backend
        const payload = {
          username,
          ciphertext: Array.from(ciphertextBytes)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""),
          authTag: Array.from(authTagBytes)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""),
          iv: Array.from(iv)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""),
        };

        const res = await fetch("http://localhost:3000/message", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        const result = await res.json();
        document.getElementById("status").innerText = result.message;
      });
  }
});
