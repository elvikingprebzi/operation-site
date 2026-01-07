const refreshBtn = document.getElementById("refresh");
const clearAllBtn = document.getElementById("clearAll");
const msg = document.getElementById("msg");
const statusGrid = document.getElementById("statusGrid");

const fieldSelect = document.getElementById("fieldId");
const passInput = document.getElementById("password");
const setBtn = document.getElementById("setBtn");
const clearBtn = document.getElementById("clearBtn");

const testFieldSelect = document.getElementById("testFieldId");
const testPassInput = document.getElementById("testPassword");
const testBtn = document.getElementById("testBtn");

const fields = Array.from({ length: 12 }, (_, i) => `f${i + 1}`);

fields.forEach(f => {
  const opt = document.createElement("option");
  opt.value = f;
  opt.textContent = f.toUpperCase();
  fieldSelect.appendChild(opt);

  const opt2 = document.createElement("option");
  opt2.value = f;
  opt2.textContent = f.toUpperCase();
  testFieldSelect.appendChild(opt2);
});

function setMessage(text, ok = true) {
  msg.textContent = text;
  msg.style.color = ok ? "var(--green)" : "var(--red)";
  setTimeout(() => (msg.textContent = ""), 2200);
}

async function loadStatus() {
  try {
    const res = await fetch("/api/admin/status");
    if (!res.ok) throw new Error("Auth or server error");
    const data = await res.json();

    statusGrid.innerHTML = "";
    for (const f of fields) {
      const isSet = data.status[f];
      const pill = document.createElement("div");
      pill.className = "pill " + (isSet ? "ok" : "");
      pill.innerHTML = `
        <span class="k">${f.toUpperCase()}</span>
        <span class="v">${isSet ? "SET ✅" : "EMPTY"}</span>
      `;
      statusGrid.appendChild(pill);
    }
  } catch {
    setMessage("Could not load status (check login).", false);
  }
}

refreshBtn.addEventListener("click", loadStatus);

setBtn.addEventListener("click", async () => {
  const fieldId = fieldSelect.value;
  const password = passInput.value;

  if (!password.trim()) return setMessage("Enter a password first.", false);

  try {
    const res = await fetch("/api/admin/set", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fieldId, password })
    });
    if (!res.ok) throw new Error();
    setMessage("Saved.");
    passInput.value = "";
    await loadStatus();
  } catch {
    setMessage("Save failed (check login).", false);
  }
});

clearBtn.addEventListener("click", async () => {
  const fieldId = fieldSelect.value;
  try {
    const res = await fetch("/api/admin/clear", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fieldId })
    });
    if (!res.ok) throw new Error();
    setMessage("Cleared.");
    await loadStatus();
  } catch {
    setMessage("Clear failed (check login).", false);
  }
});

testBtn.addEventListener("click", async () => {
  const fieldId = testFieldSelect.value;
  const password = testPassInput.value;

  if (!password.trim()) return setMessage("Enter a password to test.", false);

  try {
    const res = await fetch("/api/admin/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fieldId, password })
    });
    if (!res.ok) throw new Error();
    const data = await res.json();

    setMessage(data.ok ? "✅ Correct password" : "❌ Wrong password", data.ok);
  } catch {
    setMessage("Test failed (check login).", false);
  }
});

clearAllBtn.addEventListener("click", async () => {
  if (!confirm("Clear ALL field passwords? This cannot be undone.")) return;

  try {
    const res = await fetch("/api/admin/clearAll", {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    if (!res.ok) throw new Error();
    setMessage("All passwords cleared.");
    await loadStatus();
  } catch {
    setMessage("Clear-all failed (check login).", false);
  }
});

// Auto-load
loadStatus();