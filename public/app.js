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

/* ============================================================================
   CHANGE: Replace solved password input with a solid green button
   - Input field is removed
   - Button text: "Evil plan step X"
   - Button currently shows a placeholder alert
   - This is the ONLY behavior change in this file
============================================================================ */
function setDecrypted(card) {
  card.classList.add("decrypted");

  const fieldId = card.dataset.fieldId;
  const stepNumber = Number(fieldId.slice(1));

  const badge = card.querySelector(".badge");
  const check = card.querySelector(".check");
  const input = card.querySelector(".input");

  badge.textContent = "Decrypted";
  check.style.display = "inline";

  // Remove password input completely
  if (input) input.remove();

  // Create the action button
  const btn = document.createElement("button");
  btn.className = "solvedBtn";
  btn.textContent = `Evil plan step ${stepNumber}`;

  btn.addEventListener("click", () => {
    alert(`Step ${stepNumber} content coming soon…`);
  });

  card.appendChild(btn);
}

function resetCard(card) {
  card.classList.remove("decrypted");
  const badge = card.querySelector(".badge");
  const check = card.querySelector(".check");

  badge.textContent = "Locked";
  check.style.display = "none";

  // NOTE:
  // We do NOT recreate the input here because reset is controlled
  // from admin actions + page reload. This avoids UI edge cases.
}

function flashDenied(card) {
  const input = card.querySelector(".input");
  if (!input) return;

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

/* ============================================================================
   Existing behavior: Load cross-device solved state on page load
============================================================================ */
(async function loadSolvedOnStart() {
  try {
    const res = await fetch("/api/solved");
    const solved = await res.json();

    document.querySelectorAll(".card").forEach((card) => {
      const fieldId = card.dataset.fieldId;
      if (solved && solved[fieldId]) {
        setDecrypted(card);
      }
    });
  } catch {
    // ignore; site should still work offline
  }
})();