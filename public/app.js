async function apiStatus() {
  const r = await fetch("/api/status");
  return r.json();
}

async function apiVerify(fieldId, password) {
  const r = await fetch("/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fieldId, password }),
  });
  return r.json();
}

function setUnlocked(fieldEl, unlocked) {
  if (unlocked) fieldEl.classList.add("unlocked");
  else fieldEl.classList.remove("unlocked");
}

async function hydrate() {
  try {
    const data = await apiStatus();
    if (!data.ok) return;
    for (const [fieldId, unlocked] of Object.entries(data.status || {})) {
      const el = document.querySelector(`.field[data-field="${fieldId}"]`);
      if (el) setUnlocked(el, unlocked);
    }
  } catch (e) {
    console.warn("Status failed", e);
  }
}

function wire() {
  document.querySelectorAll(".field").forEach((fieldEl) => {
    const fieldId = fieldEl.getAttribute("data-field");
    const input = fieldEl.querySelector(".input");

    input.addEventListener("keydown", async (e) => {
      if (e.key !== "Enter") return;

      const pwd = (input.value || "").trim();
      if (!pwd) return;

      try {
        const res = await apiVerify(fieldId, pwd);
        if (res.ok) {
          input.value = "";
          setUnlocked(fieldEl, true);
        } else {
          input.value = "";
          fieldEl.classList.add("shake");
          setTimeout(() => fieldEl.classList.remove("shake"), 250);
        }
      } catch (err) {
        console.warn(err);
      }
    });
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  wire();
  await hydrate();
});