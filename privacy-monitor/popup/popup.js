document.addEventListener("DOMContentLoaded", () => {
  const scoreNum = document.getElementById("scoreNum");
  const scoreGrade = document.getElementById("scoreGrade");
  const scoreBarFill = document.getElementById("scoreBarFill");
  const domainLabel = document.getElementById("domainLabel");
  const refreshBtn = document.getElementById("refreshBtn");

  const quickStats = {
    third:   document.getElementById("statThird"),
    cookies: document.getElementById("statCookies"),
    fp:      document.getElementById("statFp"),
    hijack:  document.getElementById("statHijack"),
  };

  // chaves DEVEM bater exatamente com data-tab nos botões do HTML
  const panels = {
    third:   document.getElementById("tab-third"),
    cookies: document.getElementById("tab-cookies"),
    storage: document.getElementById("tab-storage"),
    fp:      document.getElementById("tab-fp"),
    hijack:  document.getElementById("tab-hijack"),
    score:   document.getElementById("tab-score"),
  };

  const tabs = document.querySelectorAll(".tab");

  // ── Troca de abas ────────────────────────────────────────────────────────
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const targetTab = tab.dataset.tab;

      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");

      Object.values(panels).forEach((p) => p.classList.remove("active"));
      const target = panels[targetTab];
      if (target) target.classList.add("active");
    });
  });

  // ── Renderização de listas ────────────────────────────────────────────────
  function updateList(container, items, emptyMessage) {
    if (!container) return;
    container.innerHTML = "";
    if (!items || items.length === 0) {
      container.innerHTML = `<div class="empty-state">${emptyMessage}</div>`;
      return;
    }
    items.forEach((item) => {
      const div = document.createElement("div");
      div.className = "list-item";

      if (typeof item === "string") {
        div.textContent = item;
      } else {
        // Renderização amigável por tipo de objeto
        div.innerHTML = formatItem(item);
      }
      container.appendChild(div);
    });
  }

  function formatItem(item) {
    // Domínio de 3ª parte
    if (item.types && item.count !== undefined) {
      const trackerBadge = item.isTracker
        ? `<span class="badge badge-danger">rastreador</span>`
        : `<span class="badge badge-neutral">externo</span>`;
      return `
        <div class="item-row">
          <span class="item-domain">${item.domain || "?"}</span>
          ${trackerBadge}
        </div>
        <div class="item-meta">${item.count} req · ${(item.types || []).join(", ")}</div>
      `;
    }
    // Fingerprinting
    if (item.api && item.method) {
      return `
        <div class="item-row">
          <span class="badge badge-danger">${item.api}</span>
          <span class="item-domain">${item.method}</span>
        </div>
        <div class="item-meta">${item.detail || ""}</div>
      `;
    }
    // Storage
    if (item.key !== undefined) {
      return `
        <div class="item-row">
          <span class="item-domain">${item.key}</span>
          <span class="item-meta">${item.size} bytes</span>
        </div>
        <div class="item-meta preview">${item.preview || ""}</div>
      `;
    }
    // IndexedDB
    if (item.stores) {
      return `
        <div class="item-row">
          <span class="item-domain">${item.name}</span>
          <span class="item-meta">v${item.version}</span>
        </div>
        <div class="item-meta">${item.stores.join(", ") || "sem stores"}</div>
      `;
    }
    // Cookie / supercookie / redirect
    if (item.type && item.risk) {
      return `
        <div class="item-row">
          <span class="badge badge-danger">${item.type}</span>
          <span class="item-domain">${item.domain || ""}</span>
        </div>
        <div class="item-meta">${item.risk}</div>
      `;
    }
    // Cookie syncing
    if (item.params) {
      return `
        <div class="item-row">
          <span class="item-domain">${item.domain}</span>
          <span class="badge badge-warn">${item.type}</span>
        </div>
        <div class="item-meta">${(item.params || []).join(" · ")}</div>
      `;
    }
    // Script suspeito
    if (item.reason || item.method) {
      return `
        <div class="item-row">
          <span class="badge badge-danger">suspeito</span>
          <span class="item-domain">${item.domain || ""}</span>
        </div>
        <div class="item-meta">${item.reason || item.method || ""}</div>
        <div class="item-meta preview">${(item.url || "").substring(0, 80)}</div>
      `;
    }
    // Score breakdown
    if (item.label && item.penalty !== undefined) {
      const sign = item.penalty <= 0 ? "" : "+";
      return `
        <div class="item-row">
          <span class="item-domain">${item.label}</span>
          <span class="badge badge-danger">${sign}${item.penalty}</span>
        </div>
      `;
    }
    // Redirect
    if (item.from || item.to) {
      return `
        <div class="item-row">
          <span class="badge badge-danger">${item.statusCode || "redirect"}</span>
          <span class="item-domain">${item.domain || ""}</span>
        </div>
        <div class="item-meta preview">${(item.to || "").substring(0, 80)}</div>
      `;
    }
    // iframe externo
    if (item.url && item.domain) {
      return `
        <div class="item-row">
          <span class="item-domain">${item.domain}</span>
        </div>
        <div class="item-meta preview">${item.url.substring(0, 80)}</div>
      `;
    }

    // fallback genérico
    return `<pre class="item-meta">${JSON.stringify(item, null, 2)}</pre>`;
  }

  // ── Atualizar UI com os dados recebidos ───────────────────────────────────
  function updatePopup(data) {
    const ps = data.privacyScore;

    // Score
    scoreNum.textContent = ps.score;
    scoreGrade.textContent = `Nota ${ps.grade}`;
    scoreBarFill.style.width = `${ps.score}%`;
    scoreBarFill.style.backgroundColor = ps.color;

    // Cor do score-num
    scoreNum.style.color = ps.color;

    // Domínio
    domainLabel.textContent = data.firstPartyDomain || "—";

    // Quick stats
    const thirdCount = Object.keys(data.thirdPartyDomains).length;
    const cookieCount = data.cookies.thirdParty.length;
    const fpCount = data.fingerprinting.length;
    const hijackCount = data.hijacking.suspiciousScripts.length + data.hijacking.redirectAttempts.length;

    quickStats.third.querySelector(".stat-num").textContent   = thirdCount;
    quickStats.cookies.querySelector(".stat-num").textContent = cookieCount;
    quickStats.fp.querySelector(".stat-num").textContent      = fpCount;
    quickStats.hijack.querySelector(".stat-num").textContent  = hijackCount;

    // Colorir pills com perigo
    colorPill(quickStats.third,   thirdCount > 5);
    colorPill(quickStats.cookies, cookieCount > 0);
    colorPill(quickStats.fp,      fpCount > 0);
    colorPill(quickStats.hijack,  hijackCount > 0);

    // ── Tab Terceiros ──
    const thirdPartyArr = Object.entries(data.thirdPartyDomains).map(([domain, info]) => ({
      domain, ...info
    }));
    updateList(document.getElementById("thirdPartyList"), thirdPartyArr, "Nenhum domínio de 3ª parte detectado.");

    // ── Tab Cookies ──
    document.getElementById("csc1p").textContent   = data.cookies.firstParty.length;
    document.getElementById("csc3p").textContent   = data.cookies.thirdParty.length;
    document.getElementById("cscSess").textContent = data.cookies.session.length;
    document.getElementById("cscPers").textContent = data.cookies.persistent.length;
    updateList(document.getElementById("supercookieList"), data.cookies.supercookies, "Nenhum supercookie detectado.");
    updateList(document.getElementById("cookieSyncList"), data.cookieSyncing, "Nenhuma sincronização detectada.");

    // ── Tab Storage ──
    updateList(document.getElementById("localStorageList"),   data.storage.localStorage,  "Nenhum dado em localStorage.");
    updateList(document.getElementById("sessionStorageList"), data.storage.sessionStorage, "Nenhum dado em sessionStorage.");
    updateList(document.getElementById("indexedDBList"),      data.storage.indexedDB,      "Nenhum banco IndexedDB encontrado.");

    // ── Tab Fingerprint ──
    updateList(document.getElementById("fpList"), data.fingerprinting, "Nenhuma técnica de fingerprinting detectada.");

    // ── Tab Hijacking ──
    updateList(document.getElementById("suspiciousScriptList"), data.hijacking.suspiciousScripts, "Nenhum script suspeito detectado.");
    updateList(document.getElementById("redirectList"),         data.hijacking.redirectAttempts,  "Nenhum redirecionamento suspeito.");
    updateList(document.getElementById("iframeList"),           data.hijacking.externalIframes,   "Nenhum iframe externo detectado.");

    // ── Tab Score ──
    updateList(document.getElementById("scoreBreakdown"), ps.breakdown, "Nenhuma penalidade aplicada.");
  }

  function colorPill(el, isDanger) {
    if (!el) return;
    el.querySelector(".stat-num").style.color = isDanger ? "var(--red)" : "var(--text)";
  }

  // ── Buscar dados do background ────────────────────────────────────────────
  function fetchData() {
    refreshBtn.textContent = "↻ …";
    browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
      const tabId = tabs[0].id;
      browser.runtime.sendMessage({ type: "GET_TAB_DATA", tabId }).then((response) => {
        refreshBtn.textContent = "↻ Atualizar";
        if (!response || response.error) {
          domainLabel.textContent = "Nenhum dado — recarregue a página";
          return;
        }
        updatePopup(response);
      }).catch(() => {
        refreshBtn.textContent = "↻ Atualizar";
      });
    });
  }

  refreshBtn.addEventListener("click", fetchData);
  fetchData();
});
