async function verifyField(fieldId, password) {
  const res = await fetch("/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fieldId, password }),
  });
  return res.json();
}

function markUnlocked(card) {
  card.classList.add("decrypted");

  const badge = card.querySelector(".badge");
  const check = card.querySelector(".check");
  const input = card.querySelector(".input");

  if (badge) badge.textContent = "Decrypted";
  if (check) check.style.display = "inline";

  // IMPORTANT: keep input visible + usable (your requirement)
  if (input) {
    input.type = "password";
    input.disabled = false;
    input.placeholder = "Enter encryption";
  }
}

function markLocked(card) {
  card.classList.remove("decrypted");

  const badge = card.querySelector(".badge");
  const check = card.querySelector(".check");
  const input = card.querySelector(".input");

  if (badge) badge.textContent = "Locked";
  if (check) check.style.display = "none";
  if (input) {
    input.disabled = false;
    input.value = "";
    input.type = "password";
    input.placeholder = "Enter encryption";
  }
}

async function hydrateUnlockedState() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    if (!data.ok) return;

    // default everything locked first (ensures UI always shows inputs)
    document.querySelectorAll(".card").forEach(markLocked);

    for (const [fieldId, unlocked] of Object.entries(data.status || {})) {
      const card = document.querySelector(`.card[data-field="${fieldId}"]`);
      if (!card) continue;
      if (unlocked) markUnlocked(card);
      else markLocked(card);
    }
  } catch (e) {
    // If status fails, still keep UI usable
    console.warn("Status load failed", e);
  }
}

function navigateToDecrypted(fieldId) {
  // You said you want an image page to open on success.
  // If you haven't wired decrypted.html yet, you can comment this out.
  window.location.href = `/decrypted.html?field=${encodeURIComponent(fieldId)}`;
}

function wireCards() {
  document.querySelectorAll(".card").forEach((card) => {
    const fieldId = card.getAttribute("data-field");
    const input = card.querySelector(".input");
    const btn = card.querySelector(".btn");

    const submit = async () => {
      const pwd = (input.value || "").trim();
      if (!pwd) return;

      btn.disabled = true;
      const old = btn.textContent;
      btn.textContent = "…";

      try {
        const result = await verifyField(fieldId, pwd);
        if (result.ok) {
          input.value = "";
          markUnlocked(card);
          navigateToDecrypted(fieldId);
        } else {
          input.value = "";
          card.classList.add("shake");
          setTimeout(() => card.classList.remove("shake"), 250);
        }
      } catch (e) {
        console.warn(e);
      } finally {
        btn.disabled = false;
        btn.textContent = old;
      }
    };

    btn.addEventListener("click", submit);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submit();
    });
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  wireCards();
  await hydrateUnlockedState();
});