/**
 * privacy_monitor.js
 * Script principal (background) da extensão Privacy Monitor.
 * Responsável por interceptar requisições de rede, analisar cookies,
 * detectar hijacking e calcular o Privacy Score.
 */

// ─── Estado global por aba ────────────────────────────────────────────────────
const tabData = {};

function initTab(tabId) {
    console.log(`Inicializando dados para a aba ${tabId}`);
    tabData[tabId] = {
        firstPartyDomain: null,
        thirdPartyDomains: {},
        cookies: {
        firstParty: [],
        thirdParty: [],
        session: [],
        persistent: [],
        supercookies: []
        },
        hijacking: {
        suspiciousScripts: [],
        redirectAttempts: [],
        externalIframes: []
        },
        fingerprinting: [],
        storage: {
        localStorage: [],
        sessionStorage: [],
        indexedDB: []
        },
        privacyScore: 100,
        scoreBreakdown: []
    };
}

// ─── Extração de domínio raiz ─────────────────────────────────────────────────
function getRootDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.replace(/^www\./, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  // Trata casos como .co.uk, .com.br
  const sldMap = ["co", "com", "net", "org", "edu", "gov"];
  if (parts.length >= 3 && sldMap.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function extractDomain(url) {
  try {
    return getRootDomain(new URL(url).hostname);
  } catch {
    return "";
  }
}

// ─── Domínios conhecidos de rastreamento / CDN suspeitos ──────────────────────
const KNOWN_TRACKERS = [
  "doubleclick.net", "googlesyndication.com", "google-analytics.com",
  "googletagmanager.com", "facebook.net", "facebook.com", "fbcdn.net",
  "twitter.com", "analytics.twitter.com", "linkedin.com", "ads.linkedin.com",
  "scorecardresearch.com", "quantserve.com", "outbrain.com", "taboola.com",
  "adsrvr.org", "rubiconproject.com", "openx.net", "pubmatic.com",
  "advertising.com", "criteo.com", "amazon-adsystem.com", "hotjar.com",
  "mixpanel.com", "segment.com", "amplitude.com", "heap.io",
  "mouseflow.com", "fullstory.com", "logrocket.com", "clarity.ms",
  "pardot.com", "marketo.net", "hubspot.com", "intercom.io"
];

function isKnownTracker(domain) {
  return KNOWN_TRACKERS.some(t => domain === t || domain.endsWith("." + t));
}

// ─── Scripts suspeitos (padrões de hijacking/hooking) ────────────────────────
const SUSPICIOUS_PATTERNS = [
  /beef/i, /xss/i, /hook\.js/i, /exploit/i, /payload/i,
  /keylog/i, /stealer/i, /phish/i, /inject/i, /backdoor/i,
  /c2\./i, /command.*control/i, /rat\./i, /cryptojack/i, /miner\.js/i,
  /coinhive/i, /cryptoloot/i, /webmr\.js/i
];

function isSuspiciousScript(url) {
  return SUSPICIOUS_PATTERNS.some(p => p.test(url));
}

// ─── Listener principal de requisições ───────────────────────────────────────
browser.webRequest.onBeforeRequest.addListener(
    (details) => {
      const { tabId, url, type } = details;
      if (tabId < 0) return;
      if (!tabData[tabId]) initTab(tabId);
  
      console.log(`Requisição interceptada na aba ${tabId}: ${url} (${type})`);
  
      const data = tabData[tabId];
      const reqDomain = extractDomain(url);
  
      if (type === "main_frame") {
        data.firstPartyDomain = reqDomain;
        console.log(`Domínio de 1ª parte definido: ${reqDomain}`);
        return;
      }
  
      if (!data.firstPartyDomain || !reqDomain) return;
  
      const isThirdParty = reqDomain !== data.firstPartyDomain;
  
      if (isThirdParty) {
        if (!data.thirdPartyDomains[reqDomain]) {
          data.thirdPartyDomains[reqDomain] = {
            count: 0,
            types: [],
            isTracker: isKnownTracker(reqDomain),
            urls: []
          };
        }
        const entry = data.thirdPartyDomains[reqDomain];
        entry.count++;
        if (!entry.types.includes(type)) entry.types.push(type);
        if (entry.urls.length < 5) entry.urls.push(url);
      }
    },
    { urls: ["<all_urls>"] }
);

// ─── Listener de headers de resposta (cookies + supercookies) ─────────────────
browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const { tabId, url, responseHeaders, type } = details;
    if (tabId < 0 || !tabData[tabId]) return;

    const data = tabData[tabId];
    const reqDomain = extractDomain(url);
    const isThirdParty = reqDomain !== data.firstPartyDomain;

    for (const header of responseHeaders) {
      const name = header.name.toLowerCase();
      const value = header.value || "";

      // ── Set-Cookie ─────────────────────────────────────────────────────────
      if (name === "set-cookie") {
        const cookies = value.split("\n").filter(Boolean);
        for (const cookieStr of cookies) {
          const parts = cookieStr.split(";").map(s => s.trim());
          const nameVal = parts[0] || "";
          const cookieName = nameVal.split("=")[0].trim();
          const maxAge = parts.find(p => p.toLowerCase().startsWith("max-age="));
          const expires = parts.find(p => p.toLowerCase().startsWith("expires="));
          const isSession = !maxAge && !expires;
          const isSecure = parts.some(p => p.toLowerCase() === "secure");
          const httpOnly = parts.some(p => p.toLowerCase() === "httponly");
          const sameSite = parts.find(p => p.toLowerCase().startsWith("samesite=")) || "none";

          const cookieObj = {
            name: cookieName,
            domain: reqDomain,
            isThirdParty,
            isSession,
            isPersistent: !isSession,
            isSecure,
            httpOnly,
            sameSite,
            raw: cookieStr.substring(0, 120)
          };

          if (isThirdParty) data.cookies.thirdParty.push(cookieObj);
          else data.cookies.firstParty.push(cookieObj);

          if (isSession) data.cookies.session.push(cookieObj);
          else data.cookies.persistent.push(cookieObj);
        }
      }

      // ── HSTS Supercookies ──────────────────────────────────────────────────
      if (name === "strict-transport-security") {
        if (value.includes("includeSubDomains") && isThirdParty) {
          data.cookies.supercookies.push({
            type: "HSTS Supercookie",
            domain: reqDomain,
            value: value.substring(0, 100),
            risk: "Alto — pode ser usado para rastreamento via HSTS includeSubDomains"
          });
        }
      }

      // ── ETag Supercookie (heurística) ──────────────────────────────────────
      if (name === "etag" && isThirdParty && type === "image") {
        const etagVal = value.replace(/"/g, "");
        if (etagVal.length > 16) {
          data.cookies.supercookies.push({
            type: "ETag Supercookie",
            domain: reqDomain,
            value: etagVal.substring(0, 40),
            risk: "Médio — ETag de recurso de imagem de terceiro pode ser reutilizado para identificação"
          });
        }
      }
    }

    // ── Detecção de redirecionamento suspeito ──────────────────────────────
    const status = details.statusCode;
    if ([301, 302, 303, 307, 308].includes(status) && isThirdParty) {
      const location = responseHeaders.find(h => h.name.toLowerCase() === "location");
      if (location) {
        data.hijacking.redirectAttempts.push({
          from: url,
          to: location.value,
          statusCode: status,
          domain: reqDomain
        });
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ─── Cookie Syncing ───────────────────────────────────────────────────────────
// Detecta parâmetros de URL que parecem IDs de usuário passados entre domínios
const SYNC_PARAMS = [
  "uid", "uuid", "user_id", "userid", "visitor_id", "visitorid",
  "cid", "client_id", "pid", "partner_id", "gdpr_consent",
  "id", "aid", "sid", "gid", "lid"
];

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { tabId, url, type } = details;
    if (tabId < 0 || !tabData[tabId]) return;
    if (type !== "image" && type !== "xmlhttprequest" && type !== "other") return;

    const data = tabData[tabId];
    try {
      const u = new URL(url);
      const reqDomain = getRootDomain(u.hostname);
      if (reqDomain === data.firstPartyDomain) return;

      const foundParams = [];
      for (const param of SYNC_PARAMS) {
        if (u.searchParams.has(param)) {
          const val = u.searchParams.get(param);
          if (val && val.length > 4) foundParams.push(`${param}=${val.substring(0, 20)}`);
        }
      }

      if (foundParams.length >= 2) {
        if (!data.cookieSyncing) data.cookieSyncing = [];
        data.cookieSyncing.push({
          url: url.substring(0, 150),
          domain: reqDomain,
          params: foundParams,
          type
        });
      }
    } catch {}
  },
  { urls: ["<all_urls>"] }
);

// ─── Receber mensagens do content_script ──────────────────────────────────────
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "GET_TAB_DATA") {
      const tabId = message.tabId;
      console.log(`Solicitação de dados para a aba ${tabId}`);
      if (!tabData[tabId]) {
        console.error(`Nenhum dado encontrado para a aba ${tabId}`);
        sendResponse({ error: "Nenhum dado para esta aba." });
        return true;
      }
      const data = tabData[tabId];
      const privacyResult = calculatePrivacyScore(data);
      sendResponse({
        firstPartyDomain: data.firstPartyDomain,
        thirdPartyDomains: data.thirdPartyDomains,
        cookies: data.cookies,
        hijacking: data.hijacking,
        fingerprinting: data.fingerprinting,
        storage: data.storage,
        cookieSyncing: data.cookieSyncing || [],
        privacyScore: privacyResult
      });
      return true;
    }
  });
  
// ─── Calcular Privacy Score ───────────────────────────────────────────────────
function calculatePrivacyScore(data) {
  // ── Metodologia logarítmica ────────────────────────────────────────────────
  // Cada categoria tem um peso máximo (teto). A penalidade cresce com log2
  // para que os primeiros itens pesem mais que os subsequentes.
  // Isso evita que um site com 45 cookies receba a mesma punição que
  // ter 5 cookies — a marginal é decrescente.
  //
  // Fórmula por categoria:
  //   penalidade = min(pesoBase × log2(n + 1), teto)
  //
  // Pesos calibrados para que um site típico de notícias (UOL, G1) fique ~45–55,
  // um site de e-commerce moderado fique ~60–70, e um site limpo fique ~85–100.
  //
  // Categorias e tetos:
  //   Domínios 3ª parte   → peso 7,  teto 14  (UOL tem 14 → log2(15)≈3.9 → 7×3.9≈27 → teto 14)
  //   Rastreadores conhec.→ peso 8,  teto 16
  //   Cookies 3ª parte    → peso 4,  teto 12
  //   Supercookies        → peso 6,  teto 12  (raro; penaliza forte)
  //   Canvas FP           → fixo 10
  //   WebGL FP            → fixo 10
  //   AudioContext FP     → fixo 7
  //   Script suspeito     → fixo 12 por script
  //   Redirect suspeito   → fixo 8
  //   iFrames externos    → peso 3,  teto 9
  //   Cookie syncing      → fixo 8

  const logPenalty = (n, base, cap) =>
    Math.min(Math.round(base * Math.log2(n + 1)), cap);

  let score = 100;
  const breakdown = [];

  const thirdPartyCount = Object.keys(data.thirdPartyDomains).length;
  const trackerCount    = Object.values(data.thirdPartyDomains).filter(d => d.isTracker).length;

  // ── Domínios de terceira parte ─────────────────────────────────────────────
  if (thirdPartyCount > 0) {
    const penalty = logPenalty(thirdPartyCount, 7, 14);
    score -= penalty;
    breakdown.push({
      label: `${thirdPartyCount} domínios de terceira parte`,
      penalty: -penalty,
      detail: `log2(${thirdPartyCount}+1) × 7, teto 14`,
      category: "third_party"
    });
  }

  // ── Rastreadores conhecidos ────────────────────────────────────────────────
  if (trackerCount > 0) {
    const penalty = logPenalty(trackerCount, 8, 16);
    score -= penalty;
    breakdown.push({
      label: `${trackerCount} rastreador(es) conhecido(s)`,
      penalty: -penalty,
      detail: `log2(${trackerCount}+1) × 8, teto 16`,
      category: "tracker"
    });
  }

  // ── Cookies de terceira parte ──────────────────────────────────────────────
  if (data.cookies.thirdParty.length > 0) {
    const penalty = logPenalty(data.cookies.thirdParty.length, 4, 12);
    score -= penalty;
    breakdown.push({
      label: `${data.cookies.thirdParty.length} cookies de terceira parte`,
      penalty: -penalty,
      detail: `log2(${data.cookies.thirdParty.length}+1) × 4, teto 12`,
      category: "cookie"
    });
  }

  // ── Supercookies ───────────────────────────────────────────────────────────
  if (data.cookies.supercookies.length > 0) {
    const penalty = logPenalty(data.cookies.supercookies.length, 6, 12);
    score -= penalty;
    breakdown.push({
      label: `${data.cookies.supercookies.length} supercookie(s) (HSTS/ETag)`,
      penalty: -penalty,
      detail: `log2(${data.cookies.supercookies.length}+1) × 6, teto 12`,
      category: "supercookie"
    });
  }

  // ── Fingerprinting ─────────────────────────────────────────────────────────
  const fpTypes = new Set(data.fingerprinting.map(f => f.api));
  if (fpTypes.has("Canvas")) {
    score -= 10;
    breakdown.push({ label: "Canvas fingerprinting detectado", penalty: -10, detail: "fixo", category: "fingerprint" });
  }
  if (fpTypes.has("WebGL")) {
    score -= 10;
    breakdown.push({ label: "WebGL fingerprinting detectado", penalty: -10, detail: "fixo", category: "fingerprint" });
  }
  if (fpTypes.has("AudioContext")) {
    score -= 7;
    breakdown.push({ label: "AudioContext fingerprinting detectado", penalty: -7, detail: "fixo", category: "fingerprint" });
  }

  // ── Hijacking ──────────────────────────────────────────────────────────────
  if (data.hijacking.suspiciousScripts.length > 0) {
    const penalty = Math.min(data.hijacking.suspiciousScripts.length * 12, 24);
    score -= penalty;
    breakdown.push({
      label: `${data.hijacking.suspiciousScripts.length} script(s) suspeito(s)`,
      penalty: -penalty, detail: "12 por script, teto 24", category: "hijack"
    });
  }
  if (data.hijacking.redirectAttempts.length > 0) {
    score -= 8;
    breakdown.push({
      label: `${data.hijacking.redirectAttempts.length} redirecionamento(s) suspeito(s)`,
      penalty: -8, detail: "fixo", category: "hijack"
    });
  }
  if (data.hijacking.externalIframes.length > 0) {
    const penalty = logPenalty(data.hijacking.externalIframes.length, 3, 9);
    score -= penalty;
    breakdown.push({
      label: `${data.hijacking.externalIframes.length} iframe(s) externo(s)`,
      penalty: -penalty, detail: `log2(n+1) × 3, teto 9`, category: "hijack"
    });
  }

  // ── Cookie syncing ─────────────────────────────────────────────────────────
  if (data.cookieSyncing && data.cookieSyncing.length > 0) {
    score -= 8;
    breakdown.push({
      label: `${data.cookieSyncing.length} possível(is) cookie syncing`,
      penalty: -8, detail: "fixo", category: "sync"
    });
  }

  score = Math.max(0, Math.round(score));

  let grade, color;
  if (score >= 80) { grade = "A"; color = "#22c55e"; }
  else if (score >= 60) { grade = "B"; color = "#84cc16"; }
  else if (score >= 40) { grade = "C"; color = "#eab308"; }
  else if (score >= 20) { grade = "D"; color = "#f97316"; }
  else                  { grade = "F"; color = "#ef4444"; }

  return { score, grade, color, breakdown };
}

// ─── Responder ao popup ───────────────────────────────────────────────────────
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_TAB_DATA") {
    const tabId = message.tabId;
    if (!tabData[tabId]) {
      sendResponse({ error: "Nenhum dado para esta aba." });
      return true;
    }
    const data = tabData[tabId];
    const privacyResult = calculatePrivacyScore(data);
    sendResponse({
      firstPartyDomain: data.firstPartyDomain,
      thirdPartyDomains: data.thirdPartyDomains,
      cookies: data.cookies,
      hijacking: data.hijacking,
      fingerprinting: data.fingerprinting,
      storage: data.storage,
      cookieSyncing: data.cookieSyncing || [],
      privacyScore: privacyResult
    });
    return true;
  }
});

// ─── Limpar dados ao navegar para nova página ─────────────────────────────────
browser.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0) {
      console.log(`Navegação detectada na aba ${details.tabId}`);
      initTab(details.tabId);
    }
  });

browser.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
});