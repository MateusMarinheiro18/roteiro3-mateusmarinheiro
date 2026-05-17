const tabData = {};

function initTab(tabId) {
  tabData[tabId] = {
    firstPartyDomain: null,
    thirdPartyDomains: {},
    cookies: { firstParty: [], thirdParty: [], session: [], persistent: [], supercookies: [] },
    cookieSyncing: [],
    hijacking: { suspiciousScripts: [], redirectAttempts: [], externalIframes: [] },
    fingerprinting: [],
    storage: { localStorage: [], sessionStorage: [], indexedDB: [] }
  };
}

function getRootDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.replace(/^www\./, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  const sldMap = ["co", "com", "net", "org", "edu", "gov"];
  if (parts.length >= 3 && sldMap.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function extractDomain(url) {
  try { return getRootDomain(new URL(url).hostname); }
  catch { return ""; }
}

const KNOWN_TRACKERS = [
  "doubleclick.net", "googlesyndication.com", "google-analytics.com",
  "googletagmanager.com", "googleadservices.com", "facebook.net", "fbcdn.net",
  "twitter.com", "ads.twitter.com", "linkedin.com", "ads.linkedin.com",
  "scorecardresearch.com", "quantserve.com", "outbrain.com", "taboola.com",
  "adsrvr.org", "rubiconproject.com", "openx.net", "pubmatic.com",
  "advertising.com", "criteo.com", "amazon-adsystem.com", "hotjar.com",
  "mixpanel.com", "segment.com", "amplitude.com", "heap.io",
  "mouseflow.com", "fullstory.com", "clarity.ms", "chartbeat.net",
  "permutive.com", "seedtag.com", "adnxs.com", "casalemedia.com",
  "smartadserver.com", "teads.tv", "sharethrough.com", "33across.com"
];

function isKnownTracker(domain) {
  return KNOWN_TRACKERS.some(t => domain === t || domain.endsWith("." + t));
}

const SUSPICIOUS_PATTERNS = [
  /beef/i, /\bhook\.js\b/i, /exploit/i, /payload/i, /keylog/i,
  /stealer/i, /phish/i, /backdoor/i, /cryptojack/i, /\bminer\.js\b/i,
  /coinhive/i, /cryptoloot/i, /webmr\.js/i
];

function isSuspiciousScript(url) {
  return SUSPICIOUS_PATTERNS.some(p => p.test(url));
}

const SYNC_PARAMS = [
  "uid", "uuid", "user_id", "userid", "visitor_id", "visitorid",
  "cid", "client_id", "pid", "partner_id", "gdpr_consent",
  "aid", "sid", "gid", "lid", "buyer_uid", "buyeruid"
];

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { tabId, url, type } = details;
    if (tabId < 0) return;
    if (!tabData[tabId]) initTab(tabId);

    const data = tabData[tabId];
    const reqDomain = extractDomain(url);

    if (type === "main_frame") {
      initTab(tabId);
      tabData[tabId].firstPartyDomain = reqDomain;
      console.log("[PM] main_frame → RESET + 1ª PARTE:", reqDomain, "| aba", tabId);
      return;
    }

    if (!data.firstPartyDomain) {
      console.warn("[PM] SKIP - firstPartyDomain null | aba", tabId, "| url", url.substring(0,60));
      return;
    }
    if (!reqDomain) {
      console.warn("[PM] SKIP - domínio vazio | url", url.substring(0,60));
      return;
    }

    const isThirdParty = reqDomain !== data.firstPartyDomain;

    if (isThirdParty) {
      console.log("[PM] 3ª PARTE:", reqDomain, "| tipo:", type, "| 1ª:", data.firstPartyDomain);
    }

    if (isThirdParty) {
      if (!data.thirdPartyDomains[reqDomain]) {
        data.thirdPartyDomains[reqDomain] = {
          count: 0, types: [], isTracker: isKnownTracker(reqDomain), urls: []
        };
        console.log("[PM] NOVO 3º domínio registrado:", reqDomain, "| rastreador:", isKnownTracker(reqDomain));
      }
      const entry = data.thirdPartyDomains[reqDomain];
      entry.count++;
      if (!entry.types.includes(type)) entry.types.push(type);
      if (entry.urls.length < 3) entry.urls.push(url);
    }

    if (type === "script" && isSuspiciousScript(url)) {
      if (!data.hijacking.suspiciousScripts.some(s => s.url === url)) {
        data.hijacking.suspiciousScripts.push({
          url, domain: reqDomain, isThirdParty,
          reason: "Padrão suspeito no nome/URL do script"
        });
      }
    }

    if (type === "sub_frame" && isThirdParty) {
      if (!data.hijacking.externalIframes.some(f => f.domain === reqDomain)) {
        data.hijacking.externalIframes.push({ url, domain: reqDomain });
      }
    }

    if (isThirdParty && (type === "image" || type === "xmlhttprequest" || type === "other")) {
      try {
        const u = new URL(url);
        const foundParams = [];
        for (const param of SYNC_PARAMS) {
          if (u.searchParams.has(param)) {
            const val = u.searchParams.get(param);
            if (val && val.length > 4) foundParams.push(`${param}=${val.substring(0, 24)}`);
          }
        }
        if (foundParams.length >= 2 && !data.cookieSyncing.some(s => s.domain === reqDomain)) {
          data.cookieSyncing.push({
            url: url.substring(0, 160), domain: reqDomain, params: foundParams, type
          });
        }
      } catch {}
    }
  },
  { urls: ["<all_urls>"] }
);

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const { tabId, url, responseHeaders, type, statusCode } = details;
    if (tabId < 0 || !tabData[tabId]) return;

    const data = tabData[tabId];
    const reqDomain = extractDomain(url);
    const isThirdParty = reqDomain !== data.firstPartyDomain;

    for (const header of responseHeaders) {
      const hName  = header.name.toLowerCase();
      const hValue = header.value || "";

      if (hName === "set-cookie") {
        const rawCookies = hValue.split("\n").map(s => s.trim()).filter(Boolean);
        for (const cookieStr of rawCookies) {
          const parts      = cookieStr.split(";").map(s => s.trim());
          const cookieName = (parts[0] || "").split("=")[0].trim();
          if (!cookieName) continue;

          const allCookies = [...data.cookies.firstParty, ...data.cookies.thirdParty];
          if (allCookies.some(c => c.name === cookieName && c.domain === reqDomain)) continue;

          const isSession = !parts.some(p => /^max-age=/i.test(p)) &&
                            !parts.some(p => /^expires=/i.test(p));

          const cookieObj = {
            name: cookieName, domain: reqDomain, isThirdParty,
            isSession, isPersistent: !isSession,
            isSecure:  parts.some(p => p.toLowerCase() === "secure"),
            httpOnly:  parts.some(p => p.toLowerCase() === "httponly"),
            sameSite:  (parts.find(p => /^samesite=/i.test(p)) || "SameSite=None").split("=")[1] || "None"
          };

          if (isThirdParty) data.cookies.thirdParty.push(cookieObj);
          else              data.cookies.firstParty.push(cookieObj);
          if (isSession)    data.cookies.session.push(cookieObj);
          else              data.cookies.persistent.push(cookieObj);
        }
      }

      if (hName === "strict-transport-security" && isThirdParty) {
        if (hValue.toLowerCase().includes("includesubdomains")) {
          if (!data.cookies.supercookies.some(s => s.type === "HSTS Supercookie" && s.domain === reqDomain)) {
            data.cookies.supercookies.push({
              type: "HSTS Supercookie", domain: reqDomain,
              value: hValue.substring(0, 100),
              risk: "Alto — rastreamento via HSTS includeSubDomains"
            });
          }
        }
      }

      if (hName === "etag" && isThirdParty && type === "image") {
        const etagVal = hValue.replace(/"/g, "");
        if (etagVal.length > 16) {
          if (!data.cookies.supercookies.some(s => s.type === "ETag Supercookie" && s.domain === reqDomain)) {
            data.cookies.supercookies.push({
              type: "ETag Supercookie", domain: reqDomain,
              value: etagVal.substring(0, 40),
              risk: "Médio — ETag de imagem de terceiro pode identificar usuário"
            });
          }
        }
      }
    }

    if ([301, 302, 303, 307, 308].includes(statusCode) && isThirdParty) {
      const loc = responseHeaders.find(h => h.name.toLowerCase() === "location");
      if (loc && !data.hijacking.redirectAttempts.some(r => r.from === url && r.to === loc.value)) {
        data.hijacking.redirectAttempts.push({
          from: url, to: loc.value, statusCode, domain: reqDomain
        });
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "GET_TAB_DATA") {
    const tabId = message.tabId;
    if (!tabData[tabId]) {
      console.warn("[PM] GET_TAB_DATA - sem dados para aba", tabId, "| tabData keys:", Object.keys(tabData));
      sendResponse({ error: "Nenhum dado. Recarregue a página." });
      return true;
    }
    const data = tabData[tabId];
    console.log("[PM] GET_TAB_DATA - aba", tabId,
      "| 1ª parte:", data.firstPartyDomain,
      "| 3ª parte:", Object.keys(data.thirdPartyDomains).length,
      "| cookies 3ª:", data.cookies.thirdParty.length
    );
    sendResponse({
      firstPartyDomain:  data.firstPartyDomain,
      thirdPartyDomains: data.thirdPartyDomains,
      cookies:           data.cookies,
      hijacking:         data.hijacking,
      fingerprinting:    data.fingerprinting,
      storage:           data.storage,
      cookieSyncing:     data.cookieSyncing,
      privacyScore:      calculatePrivacyScore(data)
    });
    return true;
  }

  if (message.type === "FINGERPRINTING_DETECTED") {
    const tabId = sender.tab ? sender.tab.id : null;
    if (!tabId || tabId < 0 || !tabData[tabId]) return true;
    const data = tabData[tabId];
    if (!data.fingerprinting.some(f => f.api === message.api && f.method === message.method)) {
      data.fingerprinting.push({
        api: message.api, method: message.method,
        detail: message.detail, timestamp: Date.now()
      });
    }
    return true;
  }

  if (message.type === "STORAGE_DATA") {
    const tabId = sender.tab ? sender.tab.id : null;
    if (!tabId || tabId < 0 || !tabData[tabId]) return true;
    const data = tabData[tabId];
    data.storage.localStorage   = message.localStorage  || [];
    data.storage.sessionStorage = message.sessionStorage || [];
    data.storage.indexedDB      = message.indexedDB      || [];
    return true;
  }

  if (message.type === "HIJACKING_DETECTED") {
    const tabId = sender.tab ? sender.tab.id : null;
    if (!tabId || tabId < 0 || !tabData[tabId]) return true;
    const data = tabData[tabId];
    if (message.subtype === "script_injection") {
      if (message.data && !data.hijacking.suspiciousScripts.some(s => s.url === message.data.url)) {
        data.hijacking.suspiciousScripts.push(message.data);
      }
    }
    if (message.subtype === "redirect" && message.data) {
      data.hijacking.redirectAttempts.push(message.data);
    }
    return true;
  }
});

function calculatePrivacyScore(data) {
  const logPenalty = (n, base, cap) =>
    Math.min(Math.round(base * Math.log2(n + 1)), cap);

  let score = 100;
  const breakdown = [];

  const thirdCount   = Object.keys(data.thirdPartyDomains).length;
  const trackerCount = Object.values(data.thirdPartyDomains).filter(d => d.isTracker).length;

  if (thirdCount > 0) {
    const p = logPenalty(thirdCount, 7, 14);
    score -= p;
    breakdown.push({ label: `${thirdCount} domínios de terceira parte`, penalty: -p, detail: `log₂(${thirdCount}+1)×7, teto 14`, category: "third_party" });
  }
  if (trackerCount > 0) {
    const p = logPenalty(trackerCount, 8, 16);
    score -= p;
    breakdown.push({ label: `${trackerCount} rastreador(es) conhecido(s)`, penalty: -p, detail: `log₂(${trackerCount}+1)×8, teto 16`, category: "tracker" });
  }
  if (data.cookies.thirdParty.length > 0) {
    const p = logPenalty(data.cookies.thirdParty.length, 4, 12);
    score -= p;
    breakdown.push({ label: `${data.cookies.thirdParty.length} cookies de terceira parte`, penalty: -p, detail: `log₂(n+1)×4, teto 12`, category: "cookie" });
  }
  if (data.cookies.supercookies.length > 0) {
    const p = logPenalty(data.cookies.supercookies.length, 6, 12);
    score -= p;
    breakdown.push({ label: `${data.cookies.supercookies.length} supercookie(s)`, penalty: -p, detail: `log₂(n+1)×6, teto 12`, category: "supercookie" });
  }

  const fpTypes = new Set(data.fingerprinting.map(f => f.api));
  if (fpTypes.has("Canvas"))       { score -= 10; breakdown.push({ label: "Canvas fingerprinting", penalty: -10, detail: "fixo", category: "fingerprint" }); }
  if (fpTypes.has("WebGL"))        { score -= 10; breakdown.push({ label: "WebGL fingerprinting", penalty: -10, detail: "fixo", category: "fingerprint" }); }
  if (fpTypes.has("AudioContext")) { score -= 7;  breakdown.push({ label: "AudioContext fingerprinting", penalty: -7, detail: "fixo", category: "fingerprint" }); }

  if (data.hijacking.suspiciousScripts.length > 0) {
    const p = Math.min(data.hijacking.suspiciousScripts.length * 12, 24);
    score -= p;
    breakdown.push({ label: `${data.hijacking.suspiciousScripts.length} script(s) suspeito(s)`, penalty: -p, detail: "12/script, teto 24", category: "hijack" });
  }
  if (data.hijacking.redirectAttempts.length > 0) {
    score -= 8;
    breakdown.push({ label: `${data.hijacking.redirectAttempts.length} redirecionamento(s) suspeito(s)`, penalty: -8, detail: "fixo", category: "hijack" });
  }
  if (data.hijacking.externalIframes.length > 0) {
    const p = logPenalty(data.hijacking.externalIframes.length, 3, 9);
    score -= p;
    breakdown.push({ label: `${data.hijacking.externalIframes.length} iframe(s) externo(s)`, penalty: -p, detail: "log₂(n+1)×3, teto 9", category: "hijack" });
  }
  if (data.cookieSyncing.length > 0) {
    score -= 8;
    breakdown.push({ label: `${data.cookieSyncing.length} possível(is) cookie syncing`, penalty: -8, detail: "fixo", category: "sync" });
  }

  score = Math.max(0, Math.round(score));
  let grade, color;
  if      (score >= 80) { grade = "A"; color = "#22c55e"; }
  else if (score >= 60) { grade = "B"; color = "#84cc16"; }
  else if (score >= 40) { grade = "C"; color = "#eab308"; }
  else if (score >= 20) { grade = "D"; color = "#f97316"; }
  else                  { grade = "F"; color = "#ef4444"; }

  return { score, grade, color, breakdown };
}

browser.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  // Ignora reload, back/forward e navegação interna — só reseta em link novo
  const skipTypes = ["reload", "auto_subframe", "manual_subframe", "form_submit"];
  console.log("[PM] onCommitted - aba", details.tabId, "| tipo:", details.transitionType, "| url:", details.url.substring(0,60));
  if (!skipTypes.includes(details.transitionType)) {
    console.log("[PM] RESET tabData para aba", details.tabId);
    initTab(details.tabId);
  } else {
    console.log("[PM] SKIP reset - tipo:", details.transitionType);
  }
});

browser.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
});