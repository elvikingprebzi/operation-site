const grid = document.getElementById("grid");

const fields = Array.from({ length: 12 }, (_, i) => ({
  id: `f${i + 1}`,
  label: "Enter encryption:"
}));

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
    if (e.key === "Enter") verifyField(card, input.value);
  });
  input.addEventListener("blur", () => {
    if (input.value.trim().length) verifyField(card, input.value);
  });

  return card;
}

async function verifyField(card, value) {
  if (card.classList.contains("decrypted")) return;

  const fieldId = card.dataset.fieldId;

  try {
    const res = await fetch(`/api/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fieldId, value })
    });
    const data = await res.json();

    if (data.ok) setDecrypted(card);
    else flashDenied(card);
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