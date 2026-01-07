function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return res.json();
}

async function getJson(url) {
  const res = await fetch(url);
  return res.json();
}

document.addEventListener("DOMContentLoaded", async () => {
  const fieldSelect = document.getElementById("fieldSelect");
  const pwInput = document.getElementById("pwInput");
  const out = document.getElementById("out");
  const logOut = document.getElementById("logOut");

  const setBtn = document.getElementById("setBtn");
  const resetOneBtn = document.getElementById("resetOneBtn");
  const resetAllBtn = document.getElementById("resetAllBtn");
  const refreshBtn = document.getElementById("refreshBtn");
  const refreshLogBtn = document.getElementById("refreshLogBtn");

  async function refreshState() {
    const data = await getJson("/api/admin/state");
    out.textContent = pretty(data);
  }

  async function refreshLog() {
    const data = await getJson("/api/admin/log?limit=200");
    // show newest last in a readable way
    if (!data.ok) {
      logOut.textContent = pretty(data);
      return;
    }
    logOut.textContent = data.lines.join("\n");
  }

  refreshBtn.addEventListener("click", async () => {
    await refreshState();
  });

  setBtn.addEventListener("click", async () => {
    const fieldId = fieldSelect.value;
    const password = (pwInput.value || "").trim();
    if (!password) return;

    const result = await postJson("/api/admin/set", { fieldId, password });
    pwInput.value = "";
    out.textContent = pretty(result);

    await refreshState();
    await refreshLog();
  });

  resetOneBtn.addEventListener("click", async () => {
    const fieldId = fieldSelect.value;
    const result = await postJson("/api/admin/reset", { fieldId });
    out.textContent = pretty(result);

    await refreshState();
    await refreshLog();
  });

  resetAllBtn.addEventListener("click", async () => {
    const result = await postJson("/api/admin/reset", { fieldId: "all" });
    out.textContent = pretty(result);

    await refreshState();
    await refreshLog();
  });

  refreshLogBtn.addEventListener("click", async () => {
    await refreshLog();
  });

  // initial load
  await refreshState();
  await refreshLog();
});