function setTab(tabId) {
  document.querySelectorAll(".tab-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.target === tabId);
  });

  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === tabId);
  });
}

function renderList(listElementId, items, formatter) {
  const listElement = document.getElementById(listElementId);
  listElement.innerHTML = "";

  if (!items || items.length === 0) {
    const li = document.createElement("li");
    li.textContent = "Nenhum item detectado.";
    listElement.appendChild(li);
    return;
  }

  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = formatter(item);
    listElement.appendChild(li);
  });
}

async function loadData() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  const activeTab = tabs && tabs[0];
  if (!activeTab) {
    return;
  }

  const data = await browser.runtime.sendMessage({
    type: "get-tab-data",
    tabId: activeTab.id
  });

  document.getElementById("score-value").textContent = String(data.privacyScore.score);
  document.getElementById("score-level").textContent = `Risco: ${data.privacyScore.riskLevel}`;

  renderList("third-party-list", data.thirdPartyConnections, (entry) => `${entry.domain} (${entry.resourceType})`);
  renderList("cookies-list", data.cookies, (cookie) => `${cookie.name} | ${cookie.party} parte | ${cookie.persistence}${cookie.supercookie ? " | possível supercookie" : ""}`);
  renderList(
    "storage-list",
    [
      `localStorage: ${data.storage.localStorage.count} chave(s)`,
      `sessionStorage: ${data.storage.sessionStorage.count} chave(s)`,
      `IndexedDB: ${data.storage.indexedDB.count} banco(s)`
    ],
    (entry) => entry
  );
  renderList("fingerprinting-list", data.fingerprinting, (fp) => `API: ${fp.api}`);
  renderList("hijacking-list", data.hijacking, (event) => `${event.type}: ${event.description || event.url || "evento suspeito"}`);
}

document.querySelectorAll(".tab-button").forEach((button) => {
  button.addEventListener("click", () => setTab(button.dataset.target));
});

loadData().catch((error) => {
  document.getElementById("score-level").textContent = `Erro: ${error.message}`;
});
