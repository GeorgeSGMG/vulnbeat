window.I18n = (function () {
  let currentLang = null;
  let fallbackLang = "en";
  let strings = {};
  let availableLangs = new Set();
  const subscribers = [];

  async function load(url, defaultLang, fallback) {
    try {
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);

      strings = await res.json();
      fallbackLang = fallback || "en";
      currentLang = defaultLang || fallbackLang;

      availableLangs.clear();
      Object.values(strings).forEach(entry => {
        Object.keys(entry).forEach(lang => availableLangs.add(lang));
      });
    } catch (error) {
      console.error("[I18n] Failed to load translations:", error);
    }
  }

  function t(key, vars) {
    const entry = strings[key];
    if (!entry) {
      console.warn(`[I18n] Missing translation key: "${key}"`);
      return key;
    }
    let value = entry[currentLang] ?? entry[fallbackLang] ?? key;

    if (vars || value.includes("{")) {
      const safeVars = vars || {};
      const usedKeys = new Set();

      value = value.replace(/\{(\w+)\}/g, (match, varKey) => {
        if (varKey in safeVars) {
          usedKeys.add(varKey);
          return safeVars[varKey];
        }
        console.warn(`[I18n] Missing variable "${varKey}" for key "${key}"`);
        return match;
      });

      Object.keys(safeVars).forEach(k => {
        if (!usedKeys.has(k)) {
          console.warn(`[I18n] Variable "${k}" was provided but not used in key "${key}"`);
        }
      });
    }

    return value;
  }

  function getLang() {
    return currentLang;
  }

  function getAvailableLanguages() {
    return Array.from(availableLangs);
  }

  function setLang(lang) {
    if (!availableLangs.has(lang)) {
      console.warn(`[I18n] Language "${lang}" is not available.`);
      return;
    }
    currentLang = lang;
    subscribers.forEach(callback => {
      try {
        callback(currentLang);
      } catch (e) {
        console.error("[I18n] Subscriber failed:", e);
      }
    });
  }

  function onLanguageChange(callback) {
    subscribers.push(callback);
    return () => offLanguageChange(callback);
  }

  function offLanguageChange(callback) {
    const index = subscribers.indexOf(callback);
    if (index !== -1) subscribers.splice(index, 1);
  }

  return { load, t, getLang, getAvailableLanguages, setLang, onLanguageChange, offLanguageChange };
})();