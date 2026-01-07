async function getJson(url) {
  const r = await fetch(url);
  return r.json();
}

async function postJson(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return r.json();
}

function pretty(x) {
  return JSON.stringify(x, null, 2);
}

document.addEventListener("DOMContentLoaded", async () => {
  const field = document.getElementById("field");
  const pw = document.getElementById("pw");
  const state = document.getElementById("state");
  const log = document.getElementById("log");

  async function refreshState() {
    const data = await getJson("/api/admin/state");
    state.textContent = pretty(data);
  }

  async function refreshLog() {
    const data = await getJson("/api/admin/log?limit=200");
    if (!data.ok) return (log.textContent = pretty(data));
    log.textContent = data.lines.join("\n");
  }

  document.getElementById("set").onclick = async () => {
    const p = (pw.value || "").trim();
    if (!p) return;
    await postJson("/api/admin/set", { fieldId: field.value, password: p });
    pw.value = "";
    await refreshState();
    await refreshLog();
  };

  document.getElementById("resetOne").onclick = async () => {
    await postJson("/api/admin/reset", { fieldId: field.value });
    await refreshState();
    await refreshLog();
  };

  document.getElementById("resetAll").onclick = async () => {
    await postJson("/api/admin/reset", { fieldId: "all" });
    await refreshState();
    await refreshLog();
  };

  document.getElementById("refresh").onclick = async () => {
    await refreshState();
  };

  document.getElementById("refreshLog").onclick = async () => {
    await refreshLog();
  };

  await refreshState();
  await refreshLog();
});