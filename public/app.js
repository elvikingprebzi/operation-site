async function verifyField(fieldId, password) {
  const res = await fetch("/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fieldId, password }),
  });
  return res.json();
}

// Shows the field as unlocked.
// IMPORTANT: does NOT auto-navigate by default.
function setDecrypted(card) {
  card.classList.add("decrypted");

  const badge = card.querySelector(".badge");
  const check = card.querySelector(".check");
  const input = card.querySelector(".input");

  if (badge) badge.textContent = "Decrypted";
  if (check) check.style.display = "inline";
  if (input) {
    input.value = "••••••••••";
    input.disabled = true;
  }
}

// If you want to open the subpage with image when just unlocked,
// leave this enabled:
function navigateToDecrypted(fieldId) {
  window.location.href = `/decrypted.html?field=${encodeURIComponent(fieldId)}`;
}

async function hydrateUnlockedState() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    if (!data.ok) return;

    for (const [fieldId, isUnlocked] of Object.entries(data.status || {})) {
      if (!isUnlocked) continue;
      const card = document.querySelector(`.card[data-field="${fieldId}"]`);
      if (card) setDecrypted(card);
    }
  } catch (e) {
    console.warn("Failed to load status", e);
  }
}

function wireCards() {
  const cards = document.querySelectorAll(".card");

  for (const card of cards) {
    const fieldId = card.getAttribute("data-field");
    const input = card.querySelector(".input");
    const btn = card.querySelector(".btn");

    const submit = async () => {
      const password = (input.value || "").trim();
      if (!password) return;

      btn.disabled = true;
      const oldText = btn.textContent;
      btn.textContent = "…";

      try {
        const data = await verifyField(fieldId, password);
        if (data.ok) {
          setDecrypted(card);
          // Only navigate on *fresh* unlock:
          navigateToDecrypted(fieldId);
        } else {
          input.value = "";
          input.focus();
          card.classList.add("shake");
          setTimeout(() => card.classList.remove("shake"), 250);
        }
      } catch (e) {
        console.warn(e);
      } finally {
        btn.disabled = false;
        btn.textContent = oldText;
      }
    };

    btn.addEventListener("click", submit);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submit();
    });
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  wireCards();
  await hydrateUnlockedState();
});