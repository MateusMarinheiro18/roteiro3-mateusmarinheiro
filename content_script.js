(function injectFingerprintHooks() {
  const script = document.createElement("script");
  script.textContent = `
    (() => {
      const eventName = "__privacy_monitor_event";
      const emit = (api) => {
        window.dispatchEvent(new CustomEvent(eventName, {
          detail: {
            type: "fingerprinting",
            api,
            url: window.location.href,
            timestamp: Date.now()
          }
        }));
      };

      const wrap = (target, methodName, apiName) => {
        if (!target || typeof target[methodName] !== "function") {
          return;
        }

        const original = target[methodName];
        target[methodName] = function privacyMonitorWrapped(...args) {
          try { emit(apiName); } catch (_error) {}
          return original.apply(this, args);
        };
      };

      wrap(window.HTMLCanvasElement && HTMLCanvasElement.prototype, "toDataURL", "Canvas");
      wrap(window.WebGLRenderingContext && WebGLRenderingContext.prototype, "getParameter", "WebGL");

      const AudioCtor = window.AudioContext || window.webkitAudioContext;
      if (AudioCtor && AudioCtor.prototype) {
        wrap(AudioCtor.prototype, "createOscillator", "AudioContext");
      }
    })();
  `;

  const mountPoint = document.documentElement || document.head || document.body;
  if (mountPoint) {
    mountPoint.appendChild(script);
    script.remove();
  }
})();

window.addEventListener("__privacy_monitor_event", (event) => {
  const detail = event && event.detail;
  if (!detail || detail.type !== "fingerprinting") {
    return;
  }

  browser.runtime.sendMessage({
    type: "privacy-event",
    event: "fingerprinting",
    api: detail.api,
    url: detail.url,
    timestamp: detail.timestamp,
    pageUrl: window.location.href
  });
});

async function collectStorage() {
  const localKeys = [];
  const sessionKeys = [];

  try {
    for (let i = 0; i < window.localStorage.length; i += 1) {
      const key = window.localStorage.key(i);
      if (key !== null) {
        localKeys.push(key);
      }
    }
  } catch (_error) {
    // Ignora ambientes com storage bloqueado.
  }

  try {
    for (let i = 0; i < window.sessionStorage.length; i += 1) {
      const key = window.sessionStorage.key(i);
      if (key !== null) {
        sessionKeys.push(key);
      }
    }
  } catch (_error) {
    // Ignora ambientes com storage bloqueado.
  }

  let indexedDBInfo = { count: 0, names: [] };
  try {
    if (window.indexedDB && typeof window.indexedDB.databases === "function") {
      const dbs = await window.indexedDB.databases();
      const names = (dbs || []).map((db) => db && db.name).filter(Boolean);
      indexedDBInfo = { count: names.length, names };
    }
  } catch (_error) {
    // Ignora ambientes sem suporte para listar bancos.
  }

  browser.runtime.sendMessage({
    type: "storage-report",
    pageUrl: window.location.href,
    localStorage: {
      count: localKeys.length,
      keys: localKeys
    },
    sessionStorage: {
      count: sessionKeys.length,
      keys: sessionKeys
    },
    indexedDB: indexedDBInfo
  });
}

collectStorage();
window.addEventListener("load", collectStorage, { once: true });
