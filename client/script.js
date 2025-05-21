document
  .getElementById("loginForm")
  .addEventListener("submit", async function (event) {
    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const totp = document.getElementById("totp").value;
    const message = document.getElementById("message").value;

    const payload = {
      username,
      password,
      totp,
      message,
    };

    try {
      const response = await fetch("http://localhost:3000/auth", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const result = await response.json();
      document.getElementById("status").innerText = result.message;
    } catch (error) {
      console.error("Erro ao autenticar:", error);
      document.getElementById("status").innerText =
        "Erro ao se comunicar com o servidor.";
    }
  });
