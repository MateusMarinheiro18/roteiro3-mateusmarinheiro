document.addEventListener("DOMContentLoaded", () => {
    const scoreNum = document.getElementById("scoreNum");
    const scoreGrade = document.getElementById("scoreGrade");
    const scoreBarFill = document.getElementById("scoreBarFill");
    const domainLabel = document.getElementById("domainLabel");
    const quickStats = {
      third: document.getElementById("statThird"),
      cookies: document.getElementById("statCookies"),
      fingerprint: document.getElementById("statFp"),
      hijack: document.getElementById("statHijack"),
    };
  
    const panels = {
      third: document.getElementById("tab-third"),
      cookies: document.getElementById("tab-cookies"),
      storage: document.getElementById("tab-storage"),
      fingerprint: document.getElementById("tab-fp"),
      hijack: document.getElementById("tab-hijack"),
      score: document.getElementById("tab-score"),
    };
  
    const tabs = document.querySelectorAll(".tab");
    const refreshBtn = document.getElementById("refreshBtn");
  
    // Função para alternar entre abas
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        const targetTab = tab.dataset.tab;
  
        // Atualizar abas ativas
        tabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
  
        // Atualizar painéis ativos
        Object.values(panels).forEach((panel) => panel.classList.remove("active"));
        panels[targetTab].classList.add("active");
      });
    });
  
    // Função para atualizar os dados do popup
    function updatePopup(data) {
      // Atualizar Privacy Score
      scoreNum.textContent = data.privacyScore.score;
      scoreGrade.textContent = data.privacyScore.grade;
      scoreBarFill.style.width = `${data.privacyScore.score}%`;
      scoreBarFill.style.backgroundColor = data.privacyScore.color;
  
      // Atualizar domínio
      domainLabel.textContent = data.firstPartyDomain || "—";
  
      // Atualizar estatísticas rápidas
      quickStats.third.querySelector(".stat-num").textContent = Object.keys(data.thirdPartyDomains).length;
      quickStats.cookies.querySelector(".stat-num").textContent = data.cookies.thirdParty.length;
      quickStats.fingerprint.querySelector(".stat-num").textContent = data.fingerprinting.length;
      quickStats.hijack.querySelector(".stat-num").textContent =
        data.hijacking.suspiciousScripts.length + data.hijacking.redirectAttempts.length;
  
      // Atualizar lista de domínios de 3ª parte
      const thirdPartyList = document.getElementById("thirdPartyList");
      updateList(thirdPartyList, Object.keys(data.thirdPartyDomains), "Nenhum domínio de 3ª parte detectado.");
  
      // Atualizar cookies
      document.getElementById("csc1p").textContent = data.cookies.firstParty.length;
      document.getElementById("csc3p").textContent = data.cookies.thirdParty.length;
      document.getElementById("cscSess").textContent = data.cookies.session.length;
      document.getElementById("cscPers").textContent = data.cookies.persistent.length;
      updateList(document.getElementById("supercookieList"), data.cookies.supercookies, "Nenhum supercookie detectado.");
      updateList(document.getElementById("cookieSyncList"), data.cookieSyncing, "Nenhuma sincronização detectada.");
  
      // Atualizar storage
      updateList(document.getElementById("localStorageList"), data.storage.localStorage, "Nenhum dado em localStorage.");
      updateList(document.getElementById("sessionStorageList"), data.storage.sessionStorage, "Nenhum dado em sessionStorage.");
      updateList(document.getElementById("indexedDBList"), data.storage.indexedDB, "Nenhum banco IndexedDB encontrado.");
  
      // Atualizar fingerprinting
      updateList(document.getElementById("fpList"), data.fingerprinting, "Nenhuma técnica de fingerprinting detectada.");
  
      // Atualizar hijacking
      updateList(document.getElementById("suspiciousScriptList"), data.hijacking.suspiciousScripts, "Nenhum script suspeito detectado.");
      updateList(document.getElementById("redirectList"), data.hijacking.redirectAttempts, "Nenhum redirecionamento suspeito.");
      updateList(document.getElementById("iframeList"), data.hijacking.externalIframes, "Nenhum iframe externo detectado.");
  
      // Atualizar penalidades do Privacy Score
      updateList(document.getElementById("scoreBreakdown"), data.privacyScore.breakdown, "Nenhuma penalidade ainda.");
    }
  
    // Função para atualizar listas
    function updateList(container, items, emptyMessage) {
      container.innerHTML = "";
      if (items.length === 0) {
        container.innerHTML = `<div class="empty-state">${emptyMessage}</div>`;
      } else {
        items.forEach((item) => {
          const div = document.createElement("div");
          div.className = "list-item";
          div.textContent = typeof item === "string" ? item : JSON.stringify(item, null, 2);
          container.appendChild(div);
        });
      }
    }
  
    // Função para solicitar dados ao background script
    function fetchData() {
      browser.runtime.sendMessage({ type: "GET_TAB_DATA", tabId: null }).then((response) => {
        if (response.error) {
          console.error("Erro ao obter dados:", response.error);
          return;
        }
        updatePopup(response);
      });
    }
  
    // Atualizar dados ao clicar no botão de refresh
    refreshBtn.addEventListener("click", fetchData);
  
    // Buscar dados ao carregar o popup
    fetchData();
  });