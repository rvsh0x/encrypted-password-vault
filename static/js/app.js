// JS frontend minimaliste pour l'interface web locale du vault.
// - Récupère un token CSRF via /api/session
// - Toutes les requêtes mutantes envoient X-CSRF-Token
// - Aucune communication externe, tout pointe vers /api/* en local.

(function () {
  let CSRF_TOKEN = null;

  async function fetchSession() {
    const res = await fetch("/api/session", {
      method: "GET",
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error("Erreur session");
    }
    const data = await res.json();
    CSRF_TOKEN = data.csrf_token || null;
    return data;
  }

  function normalizeErrorMessage(payload, status) {
    if (!payload) return `Erreur HTTP ${status}`;
    const detail = payload.detail ?? payload.error;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail.length) {
      const first = detail[0];
      if (typeof first === "string") return first;
      if (first && typeof first === "object") {
        if (typeof first.msg === "string") return first.msg;
        if (typeof first.detail === "string") return first.detail;
      }
      try {
        return JSON.stringify(detail);
      } catch {
        return "Erreur inconnue";
      }
    }
    try {
      return JSON.stringify(detail);
    } catch {
      return `Erreur HTTP ${status}`;
    }
  }

  async function apiRequest(path, options = {}) {
    const method = options.method || "GET";
    const headers = options.headers || {};
    headers["Accept"] = "application/json";
    const isSafe = method === "GET" || method === "HEAD" || method === "OPTIONS";
    if (!isSafe && CSRF_TOKEN) {
      headers["X-CSRF-Token"] = CSRF_TOKEN;
    }
    const init = {
      method,
      headers,
      credentials: "include",
    };
    if (options.body) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    const res = await fetch(path, init);
    let payload = null;
    try {
      payload = await res.json();
    } catch {
      payload = null;
    }
    if (!res.ok) {
      const msg = normalizeErrorMessage(payload, res.status);
      throw new Error(msg);
    }
    return payload;
  }

  function showToast(message, kind = "info") {
    let root = document.getElementById("toast-root");
    if (!root) {
      root = document.createElement("div");
      root.id = "toast-root";
      root.className = "toast-container";
      document.body.appendChild(root);
    }
    const el = document.createElement("div");
    el.className = "toast";
    if (kind === "error") {
      el.style.borderColor = "#f97373";
    } else if (kind === "success") {
      el.style.borderColor = "#22c55e";
    }
    el.textContent = message;
    root.appendChild(el);
    setTimeout(() => {
      el.remove();
    }, 3500);
  }

  async function ensureUnlockedOrRedirect() {
    try {
      const session = await fetchSession();
      if (!session.unlocked) {
        window.location.href = "/";
        return null;
      }
      return session;
    } catch (e) {
      console.error(e);
      window.location.href = "/";
      return null;
    }
  }

  function setupGlobalLockButton() {
    const btn = document.getElementById("lock-btn");
    if (!btn) return;
    btn.addEventListener("click", async () => {
      try {
        await apiRequest("/api/lock", { method: "POST" });
        showToast("Coffre verrouillé.", "success");
        setTimeout(() => (window.location.href = "/"), 500);
      } catch (e) {
        showToast(e.message, "error");
      }
    });
  }

  function setupAutoSessionPolling() {
    const pathsNeedingPoll = ["/dashboard", "/add", "/settings"];
    const path = window.location.pathname;
    if (!pathsNeedingPoll.some((p) => path.startsWith(p))) return;
    setInterval(async () => {
      try {
        const session = await fetchSession();
        if (!session.unlocked) {
          showToast("Coffre auto-verrouillé après inactivité.", "info");
          window.location.href = "/";
        }
      } catch {
        // ignore
      }
    }, 60000);
  }

  // --- Pages ---

  async function initUnlockPage() {
    try {
      const session = await fetchSession();
      if (session.unlocked) {
        window.location.href = "/dashboard";
        return;
      }
    } catch {
      // ignore, on reste sur la page
    }
    const form = document.getElementById("unlock-form");
    const errorEl = document.getElementById("unlock-error");
    const toggleBtn = document.getElementById("toggle-master");
    const pwdInput = document.getElementById("master_password");
    if (toggleBtn && pwdInput) {
      toggleBtn.addEventListener("click", () => {
        pwdInput.type = pwdInput.type === "password" ? "text" : "password";
      });
    }
    if (!form) return;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      errorEl.style.display = "none";
      const master_password = pwdInput.value;
      // On envoie toujours une chaîne pour éviter les erreurs de validation Pydantic
      const vault_path = document.getElementById("vault_path").value || "";
      try {
        await apiRequest("/api/unlock", {
          method: "POST",
          body: { master_password, vault_path },
        });
        showToast("Coffre déverrouillé.", "success");
        window.location.href = "/dashboard";
      } catch (err) {
        errorEl.textContent = err.message || "Échec de déverrouillage.";
        errorEl.style.display = "block";
      }
    });
  }

  async function initDashboardPage() {
    const session = await ensureUnlockedOrRedirect();
    if (!session) return;
    const tbody = document.getElementById("entries-body");
    const noEntries = document.getElementById("no-entries");
    const searchInput = document.getElementById("search");
    const sortSite = document.getElementById("sort-site");
    const sortUser = document.getElementById("sort-username");
    let entries = [];
    let sortKey = "site";
    let sortAsc = true;

    async function loadEntries() {
      try {
        entries = await apiRequest("/api/entries");
        render();
      } catch (e) {
        showToast(e.message, "error");
      }
    }

    function render() {
      if (!tbody) return;
      tbody.innerHTML = "";
      const q = (searchInput?.value || "").toLowerCase();
      let filtered = entries.slice();
      if (q) {
        filtered = filtered.filter((e) => {
          return (
            (e.site || "").toLowerCase().includes(q) ||
            (e.username || "").toLowerCase().includes(q)
          );
        });
      }
      filtered.sort((a, b) => {
        const va = (a[sortKey] || "").toLowerCase();
        const vb = (b[sortKey] || "").toLowerCase();
        if (va < vb) return sortAsc ? -1 : 1;
        if (va > vb) return sortAsc ? 1 : -1;
        return 0;
      });
      if (filtered.length === 0) {
        if (noEntries) noEntries.style.display = "block";
        return;
      }
      if (noEntries) noEntries.style.display = "none";
      for (const e of filtered) {
        const tr = document.createElement("tr");
        tr.className = "entry-row";
        const tdSite = document.createElement("td");
        tdSite.className = "table-td";
        const link = document.createElement("a");
        link.href = `/entry/${encodeURIComponent(e.id)}`;
        link.textContent = e.site || "(sans site)";
        link.className = "entry-link";
        tdSite.appendChild(link);
        const tdUser = document.createElement("td");
        tdUser.className = "table-td";
        tdUser.textContent = e.username || "";
        const tdActions = document.createElement("td");
        tdActions.className = "table-td text-right";
        const viewBtn = document.createElement("a");
        viewBtn.href = `/entry/${encodeURIComponent(e.id)}`;
        viewBtn.className = "btn btn-secondary";
        viewBtn.textContent = "Détails";
        tdActions.appendChild(viewBtn);
        tr.appendChild(tdSite);
        tr.appendChild(tdUser);
        tr.appendChild(tdActions);
        tbody.appendChild(tr);
      }
    }

    if (searchInput) {
      searchInput.addEventListener("input", render);
    }
    if (sortSite) {
      sortSite.addEventListener("click", () => {
        if (sortKey === "site") sortAsc = !sortAsc;
        else {
          sortKey = "site";
          sortAsc = true;
        }
        render();
      });
    }
    if (sortUser) {
      sortUser.addEventListener("click", () => {
        if (sortKey === "username") sortAsc = !sortAsc;
        else {
          sortKey = "username";
          sortAsc = true;
        }
        render();
      });
    }

    await loadEntries();
  }

  function passwordStrengthScore(pwd) {
    let score = 0;
    if (!pwd) return 0;
    if (pwd.length >= 12) score++;
    if (pwd.length >= 16) score++;
    if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    if (score > 4) score = 4;
    return score;
  }

  function updateStrengthUI(pwd) {
    const fill = document.getElementById("password-strength-fill");
    const label = document.getElementById("password-strength-label");
    if (!fill || !label) return;
    const score = passwordStrengthScore(pwd);
    fill.className = "strength-fill strength-" + score;
    const texts = ["Très faible", "Faible", "Moyen", "Fort", "Très fort"];
    label.textContent = texts[score] || "";
  }

  async function initAddEntryPage() {
    const session = await ensureUnlockedOrRedirect();
    if (!session) return;
    const form = document.getElementById("add-entry-form");
    const pwdInput = document.getElementById("password");
    const toggle = document.getElementById("toggle-password");
    const genBtn = document.getElementById("generate-password-btn");
    const genLen = document.getElementById("gen-length");
    const genSpecial = document.getElementById("gen-special");

    if (toggle && pwdInput) {
      toggle.addEventListener("click", () => {
        pwdInput.type = pwdInput.type === "password" ? "text" : "password";
      });
    }
    if (pwdInput) {
      pwdInput.addEventListener("input", () => updateStrengthUI(pwdInput.value));
    }
    if (genBtn && genLen && genSpecial) {
      genBtn.addEventListener("click", async () => {
        const length = parseInt(genLen.value || "20", 10) || 20;
        const noSpecial = !genSpecial.checked;
        try {
          const resp = await apiRequest("/api/generate-password", {
            method: "POST",
            body: {
              length,
              no_special: noSpecial,
            },
          });
          if (pwdInput) {
            pwdInput.value = resp.password;
            updateStrengthUI(resp.password);
          }
          showToast("Mot de passe généré.", "success");
        } catch (e) {
          showToast(e.message, "error");
        }
      });
    }
    if (!form) return;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const site = document.getElementById("site").value;
      const username = document.getElementById("username").value;
      const password = pwdInput.value;
      const notes = document.getElementById("notes").value || null;
      try {
        await apiRequest("/api/entries", {
          method: "POST",
          body: { site, username, password, notes },
        });
        showToast("Entrée ajoutée.", "success");
        window.location.href = "/dashboard";
      } catch (err) {
        showToast(err.message, "error");
      }
    });
  }

  function getEntryIdFromPath() {
    const parts = window.location.pathname.split("/");
    return parts[parts.length - 1] || null;
  }

  async function copyToClipboard(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch {
      // fallback
    }
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }

  async function initViewEntryPage() {
    const session = await ensureUnlockedOrRedirect();
    if (!session) return;
    const id = getEntryIdFromPath();
    if (!id) {
      showToast("ID d'entrée manquant.", "error");
      return;
    }
    const siteInput = document.getElementById("entry-site");
    const userInput = document.getElementById("entry-username");
    const pwdInput = document.getElementById("entry-password");
    const notesInput = document.getElementById("entry-notes");
    const copyUserBtn = document.getElementById("copy-username-btn");
    const copyPwdBtn = document.getElementById("copy-password-btn");
    const togglePwdBtn = document.getElementById("toggle-entry-password");
    const saveBtn = document.getElementById("save-entry-btn");
    const delBtn = document.getElementById("delete-entry-btn");

    try {
      const entry = await apiRequest(`/api/entries/${encodeURIComponent(id)}`);
      if (siteInput) siteInput.value = entry.site || "";
      if (userInput) userInput.value = entry.username || "";
      if (pwdInput) pwdInput.value = entry.password || "";
      if (notesInput) notesInput.value = entry.notes || "";
    } catch (e) {
      showToast(e.message, "error");
    }

    if (togglePwdBtn && pwdInput) {
      togglePwdBtn.addEventListener("click", () => {
        pwdInput.type = pwdInput.type === "password" ? "text" : "password";
      });
    }
    if (copyUserBtn && userInput) {
      copyUserBtn.addEventListener("click", async () => {
        if (await copyToClipboard(userInput.value || "")) {
          showToast("Identifiant copié.", "success");
        }
      });
    }
    if (copyPwdBtn && pwdInput) {
      copyPwdBtn.addEventListener("click", async () => {
        if (await copyToClipboard(pwdInput.value || "")) {
          showToast("Mot de passe copié.", "success");
        }
      });
    }
    if (saveBtn) {
      saveBtn.addEventListener("click", async () => {
        try {
          await apiRequest(`/api/entries/${encodeURIComponent(id)}`, {
            method: "PUT",
            body: {
              site: siteInput.value,
              username: userInput.value,
              password: pwdInput.value,
              notes: notesInput.value || null,
            },
          });
          showToast("Entrée mise à jour.", "success");
        } catch (e) {
          showToast(e.message, "error");
        }
      });
    }
    if (delBtn) {
      delBtn.addEventListener("click", async () => {
        if (!confirm("Supprimer définitivement cette entrée ?")) return;
        try {
          await apiRequest(`/api/entries/${encodeURIComponent(id)}`, {
            method: "DELETE",
          });
          showToast("Entrée supprimée.", "success");
          setTimeout(() => (window.location.href = "/dashboard"), 500);
        } catch (e) {
          showToast(e.message, "error");
        }
      });
    }
  }

  async function initSettingsPage() {
    const session = await ensureUnlockedOrRedirect();
    if (!session) return;
    const input = document.getElementById("auto-lock-minutes");
    if (input && session.auto_lock_minutes) {
      input.value = session.auto_lock_minutes;
    }
    const form = document.getElementById("auto-lock-form");
    if (!form) return;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const minutes = parseInt(input.value || "10", 10) || 10;
      try {
        const resp = await apiRequest("/api/settings/auto-lock", {
          method: "POST",
          body: { minutes },
        });
        showToast(`Auto-verrouillage après ${resp.minutes} minutes.`, "success");
      } catch (err) {
        showToast(err.message, "error");
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    const path = window.location.pathname;
    setupGlobalLockButton();
    setupAutoSessionPolling();
    if (path === "/" || path === "/index.html") {
      initUnlockPage();
    } else if (path.startsWith("/dashboard")) {
      initDashboardPage();
    } else if (path.startsWith("/add")) {
      initAddEntryPage();
    } else if (path.startsWith("/entry/")) {
      initViewEntryPage();
    } else if (path.startsWith("/settings")) {
      initSettingsPage();
    }
  });
})();

