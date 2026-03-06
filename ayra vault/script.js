// ======== Simple Ayra Vault — Crypto Helpers (Web Crypto API) =========

    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder();

    const SALT_KEY = "ayra_vault_salt";
    const VAULT_KEY = "ayra_vault_data";

    let masterKey = null;       // CryptoKey after login
    let vaultData = [];         // Decrypted in-memory array

    function toBase64(bytes) {
      return btoa(String.fromCharCode(...new Uint8Array(bytes)));
    }

    function fromBase64(str) {
      return Uint8Array.from(atob(str), c => c.charCodeAt(0));
    }

    async function ensureSalt() {
      let saltB64 = localStorage.getItem(SALT_KEY);
      if (!saltB64) {
        const salt = new Uint8Array(16);
        crypto.getRandomValues(salt);
        saltB64 = toBase64(salt);
        localStorage.setItem(SALT_KEY, saltB64);
      }
      return fromBase64(saltB64);
    }

    async function deriveKeyFromPassword(password) {
      const salt = await ensureSalt();
      const baseKey = await crypto.subtle.importKey(
        "raw",
        textEncoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );

      const key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: 120000, // Kafi decent for personal use
          hash: "SHA-256",
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );

      return key;
    }

    async function encryptVaultData(key, dataObj) {
      const iv = new Uint8Array(12);
      crypto.getRandomValues(iv);

      const plaintext = textEncoder.encode(JSON.stringify(dataObj));

      const cipherBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        plaintext
      );

      return {
        iv: toBase64(iv),
        data: toBase64(cipherBuffer),
      };
    }

    async function decryptVaultData(key, cipherObj) {
      const iv = fromBase64(cipherObj.iv);
      const data = fromBase64(cipherObj.data);

      const plainBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        data
      );

      const text = textDecoder.decode(plainBuffer);
      return JSON.parse(text);
    }

    function loadRawVault() {
      const raw = localStorage.getItem(VAULT_KEY);
      if (!raw) return null;

      try {
        return JSON.parse(raw);
      } catch {
        return null;
      }
    }

    async function saveVault() {
      if (!masterKey) return;
      const cipherObj = await encryptVaultData(masterKey, vaultData);
      localStorage.setItem(VAULT_KEY, JSON.stringify(cipherObj));
      updateCounts();
      renderVault();
    }

    // ============== UI Logic ================

    const loginScreen = document.getElementById("login-screen");
    const appScreen = document.getElementById("app-screen");
    const unlockBtn = document.getElementById("unlock-btn");
    const masterInput = document.getElementById("master-password");
    const loginMessage = document.getElementById("login-message");
    const loginSuccess = document.getElementById("login-success");
    const lockBtn = document.getElementById("lock-btn");

    const itemTypeSelect = document.getElementById("item-type");
    const itemTitleInput = document.getElementById("item-title");
    const itemUsernameInput = document.getElementById("item-username");
    const itemValueInput = document.getElementById("item-value");
    const valueLabel = document.getElementById("value-label");
    const usernameRow = document.getElementById("username-row");
    const addBtn = document.getElementById("add-btn");

    const entryList = document.getElementById("entry-list");
    const noItemsText = document.getElementById("no-items-text");
    const entryCountSpan = document.getElementById("entry-count");

    function showLoginError(msg) {
      loginMessage.textContent = msg;
      loginMessage.classList.remove("hidden");
      loginSuccess.classList.add("hidden");
    }

    function showLoginSuccess(msg) {
      loginSuccess.textContent = msg;
      loginSuccess.classList.remove("hidden");
      loginMessage.classList.add("hidden");
    }

    function clearLoginMessages() {
      loginMessage.classList.add("hidden");
      loginSuccess.classList.add("hidden");
    }

    function updateCounts() {
      entryCountSpan.textContent = vaultData.length.toString();
    }

    function renderVault() {
      entryList.innerHTML = "";

      if (!vaultData.length) {
        noItemsText.style.display = "block";
      } else {
        noItemsText.style.display = "none";
      }

      vaultData
        .slice()
        .sort((a, b) => b.createdAt - a.createdAt)
        .forEach((entry) => {
          const card = document.createElement("div");
          card.className = "entry-card";

          const title = document.createElement("div");
          title.className = "entry-title";
          title.textContent = entry.title || "(Untitled)";

          const meta = document.createElement("div");
          meta.className = "entry-meta";

          const typeBadge = document.createElement("span");
          typeBadge.className = "entry-type";
          typeBadge.textContent = entry.type === "password" ? "Password" : "Note";

          const created = new Date(entry.createdAt);
          const dateSpan = document.createElement("span");
          dateSpan.textContent =
            "Saved " + created.toLocaleDateString() + " • " + created.toLocaleTimeString();

          meta.appendChild(typeBadge);
          if (entry.username) {
            const userSpan = document.createElement("span");
            userSpan.textContent = "• " + entry.username;
            meta.appendChild(userSpan);
          }
          meta.appendChild(dateSpan);

          const content = document.createElement("div");
          content.className = "entry-content";
          content.textContent = entry.value;

          const actions = document.createElement("div");
          actions.className = "entry-actions";

          const actionsLeft = document.createElement("div");
          actionsLeft.className = "entry-actions-left";

          const toggleBtn = document.createElement("button");
          toggleBtn.className = "secondary small-btn";
          toggleBtn.textContent = "👁 Show";
          let visible = false;
          toggleBtn.addEventListener("click", () => {
            visible = !visible;
            if (visible) {
              content.style.display = "block";
              toggleBtn.textContent = "Hide";
            } else {
              content.style.display = "none";
              toggleBtn.textContent = "👁 Show";
            }
          });

          const copyBtn = document.createElement("button");
          copyBtn.className = "secondary small-btn";
          copyBtn.textContent = "Copy";
          copyBtn.addEventListener("click", () => {
            navigator.clipboard.writeText(entry.value).then(
              () => {
                copyBtn.textContent = "✔ Copied";
                setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
              },
              () => {
                copyBtn.textContent = "Error";
                setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
              }
            );
          });

          const deleteBtn = document.createElement("button");
          deleteBtn.className = "secondary small-btn";
          deleteBtn.textContent = "🗑 Delete";
          deleteBtn.addEventListener("click", () => {
            if (!confirm("Delete this item from vault?")) return;
            vaultData = vaultData.filter((e) => e.id !== entry.id);
            saveVault();
          });

          actionsLeft.appendChild(toggleBtn);
          actionsLeft.appendChild(copyBtn);

          const badge = document.createElement("span");
          badge.className = "badge-count";
          badge.textContent = "#" + entry.id.toString().slice(-5);

          actions.appendChild(actionsLeft);
          actions.appendChild(deleteBtn);

          card.appendChild(title);
          card.appendChild(meta);
          card.appendChild(content);
          card.appendChild(actions);
          card.appendChild(badge);

          entryList.appendChild(card);
        });

      updateCounts();
    }

    function resetEntryForm() {
      itemTitleInput.value = "";
      itemUsernameInput.value = "";
      itemValueInput.value = "";
    }

    itemTypeSelect.addEventListener("change", () => {
      const type = itemTypeSelect.value;
      if (type === "password") {
        valueLabel.textContent = "Password";
        itemValueInput.placeholder = "Enter password or secret key...";
        usernameRow.style.display = "block";
      } else {
        valueLabel.textContent = "Note";
        itemValueInput.placeholder = "Write your note, idea, or secret...";
        usernameRow.style.display = "none";
      }
    });

    addBtn.addEventListener("click", async () => {
      if (!masterKey) return;

      const type = itemTypeSelect.value;
      const title = itemTitleInput.value.trim();
      const username = itemUsernameInput.value.trim();
      const value = itemValueInput.value.trim();

      if (!title || !value) {
        alert("Title and value are required.");
        return;
      }

      const entry = {
        id: Date.now(),
        type,
        title,
        username: type === "password" ? username || "" : "",
        value,
        createdAt: Date.now(),
      };

      vaultData.push(entry);
      resetEntryForm();
      await saveVault();
    });

    lockBtn.addEventListener("click", () => {
      masterKey = null;
      vaultData = [];
      appScreen.classList.add("hidden");
      loginScreen.classList.remove("hidden");
      masterInput.value = "";
      clearLoginMessages();
    });

    async function handleUnlock() {
      clearLoginMessages();
      const password = masterInput.value;

      if (!password) {
        showLoginError("Please enter your master password.");
        return;
      }

      try {
        const key = await deriveKeyFromPassword(password);
        masterKey = key;

        const raw = loadRawVault();

        if (!raw) {
          // Pehli baar – blank vault bana dete hain
          vaultData = [];
          await saveVault();
          showLoginSuccess("New vault created. Remember this master password!");
        } else {
          // Purana vault – decrypt karna padega
          try {
            vaultData = await decryptVaultData(masterKey, raw);
            showLoginSuccess("Vault unlocked successfully.");
          } catch (e) {
            masterKey = null;
            vaultData = [];
            showLoginError(
              "Could not decrypt vault. Master password galat hai ya data corrupt ho gaya."
            );
            return;
          }
        }

        // UI switch
        loginScreen.classList.add("hidden");
        appScreen.classList.remove("hidden");
        renderVault();
      } catch (e) {
        console.error(e);
        showLoginError("Something went wrong while unlocking. Try again.");
      }
    }

    unlockBtn.addEventListener("click", handleUnlock);

    masterInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        handleUnlock();
      }
    });