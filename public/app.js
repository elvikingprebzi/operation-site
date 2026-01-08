const grid = document.getElementById("grid");

const fields = Array.from({ length: 12 }, (_, i) => ({
  id: `f${i + 1}`,
  label: "Enter encryption:"
}));

// ===== PERSISTED PASSWORD STORAGE =====
const STORAGE_PREFIX = "op_saved_pw_";
const storageKey = (fieldId) => `${STORAGE_PREFIX}${fieldId}`;

function savePassword(fieldId, value) {
  try {
    localStorage.setItem(storageKey(fieldId), value);
  } catch {
    // ignore (private mode / storage blocked)
  }
}

function loadPassword(fieldId) {
  try {
    return localStorage.getItem(storageKey(fieldId)) || "";
  } catch {
    return "";
  }
}

function clearPassword(fieldId) {
  try {
    localStorage.removeItem(storageKey(fieldId));
  } catch {
    // ignore
  }
}
// ======================================

function makeCard(field) {
  const card = document.createElement("div");
  card.className = "card";
  card.dataset.fieldId = field.id;

  card.innerHTML = `
    <div class="labelrow">
      <div class="label">${field.label}</div>
      <div class="status">
        <span class="check" aria-hidden="true" style="display:none;">✅</span>
        <span class="badge">Locked</span>
      </div>
    </div>
    <input class="input" type="password" autocomplete="off" spellcheck="false" />
    <div class="hint">Press Enter to verify</div>
  `;

  const input = card.querySelector(".input");

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") verifyField(card, input.value, { shouldStore: true });
  });

  input.addEventListener("blur", () => {
    if (input.value.trim().length) verifyField(card, input.value, { shouldStore: true });
  });

  // If we have a stored password, prefill and verify automatically
  const saved = loadPassword(field.id);
  if (saved) {
    input.value = saved;
    // verify after the element is in DOM
    queueMicrotask(() => verifyField(card, saved, { shouldStore: false }));
  }

  return card;
}

async function verifyField(card, value, opts = {}) {
  if (card.classList.contains("decrypted")) return;

  const { shouldStore = false } = opts;
  const fieldId = card.dataset.fieldId;

  try {
    const res = await fetch(`/api/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fieldId, value })
    });

    const data = await res.json().catch(() => ({}));

    if (data.ok) {
      // Store ONLY when correct (and only on user action)
      if (shouldStore) savePassword(fieldId, value);
      setDecrypted(card);
    } else {
      // Optional: if a stored password is wrong (e.g. admin changed it), clear it
      // This prevents it from "failing forever" on refresh.
      if (!shouldStore) clearPassword(fieldId);
      flashDenied(card);
    }
  } catch {
    flashError(card);
  }
}

function setDecrypted(card) {
  card.classList.add("decrypted");
  const badge = card.querySelector(".badge");
  const check = card.querySelector(".check");
  const input = card.querySelector(".input");

  badge.textContent = "Decrypted";
  check.style.display = "inline";
  input.type = "text";
  input.value = "••••••••••";
  input.disabled = true;
}

function resetCard(card) {
  card.classList.remove("decrypted");
  const badge = card.querySelector(".badge");
  const check = card.querySelector(".check");
  const input = card.querySelector(".input");

  // If you have a reset button elsewhere and you want it to also forget saved pw:
  // clearPassword(card.dataset.fieldId);

  badge.textContent = "Locked";
  check.style.display = "none";
  input.disabled = false;
  input.type = "password";
  input.value = "";
  input.focus();
}

function flashDenied(card) {
  const input = card.querySelector(".input");
  input.animate(
    [
      { transform: "translateX(0px)" },
      { transform: "translateX(-6px)" },
      { transform: "translateX(6px)" },
      { transform: "translateX(-4px)" },
      { transform: "translateX(4px)" },
      { transform: "translateX(0px)" }
    ],
    { duration: 260 }
  );
}

function flashError(card) {
  const badge = card.querySelector(".badge");
  badge.textContent = "Offline";
  setTimeout(() => (badge.textContent = "Locked"), 900);
}

fields.forEach((f) => grid.appendChild(makeCard(f)));