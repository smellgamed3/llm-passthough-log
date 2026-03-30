/* ═══════════════════════════════════════════════════
   LLM Log Search — Public Search Page JS
   ═══════════════════════════════════════════════════ */

const state = {
  page: 1,
  pages: 1,
  pageSize: 20,
  filters: {},
  pathFilter: "chat/completions",
  selectedTraceId: null,
  detailEntry: null,
  inputMode: "key", // "key" or "hash"
  // Key management - stored in localStorage as hashes only
  keys: [], // [{id, hash, label, active, count}]
};

const STORAGE_KEY = "llm_search_api_keys";

/* ── Utility ──────────────────────────────────────── */

function esc(v) {
  return String(v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

function fpColor(fp) {
  if (!fp) return "transparent";
  let h = 0;
  for (let i = 0; i < fp.length; i++) h = ((h << 5) - h + fp.charCodeAt(i)) | 0;
  return `hsl(${((h % 360) + 360) % 360}, 60%, 55%)`;
}

function maskKeyDisplay(key) {
  if (!key) return "-";
  const s = key.trim();
  if (s.length <= 8) return s.slice(0, 2) + "***";
  return s.slice(0, 6) + "…" + s.slice(-4);
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function _copyToClipboard(text, feedbackEl) {
  const ok = () => { if (feedbackEl) { feedbackEl.textContent = '✓'; setTimeout(() => feedbackEl.textContent = '📋', 1500); } };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(ok).catch(() => { _copyFallback(text); ok(); });
  } else {
    _copyFallback(text); ok();
  }
}

function _copyFallback(text) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
}

function fmtTime(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("zh-CN", { month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit", second:"2-digit" });
}

function fmtTimeFull(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}

function fmtMs(v) {
  if (v == null) return "-";
  if (v >= 1000) return (v / 1000).toFixed(2) + "s";
  return v.toFixed(0) + "ms";
}

function fmtBytes(b) {
  if (!b) return "-";
  if (b < 1024) return b + " B";
  return (b / 1024).toFixed(1) + " KB";
}

function fmtCost(v) {
  if (!v || v <= 0) return "";
  if (v < 0.001) return "$" + v.toFixed(6);
  if (v < 0.01) return "$" + v.toFixed(4);
  return "$" + v.toFixed(3);
}

function toLocalISO(d) {
  const off = d.getTimezoneOffset();
  const local = new Date(d.getTime() - off * 60000);
  return local.toISOString().slice(0, 16);
}

/* ── Sensitive data display helpers ───────────────── */

const SENSITIVE_KEYS = new Set([
  "authorization", "proxy_authorization", "x_api_key", "api_key", "apikey",
  "downstream_apikey", "access_token", "refresh_token", "client_secret", "secret", "token",
]);

function normalizeSensitiveKey(key) {
  return String(key || "").trim().toLowerCase().replace(/-/g, "_");
}

function maskSecretText(value) {
  const text = String(value || "").trim();
  if (!text) return text;
  if (text.toLowerCase().startsWith("bearer ")) return "Bearer " + maskSecretText(text.slice(7).trim());
  if (text.toLowerCase().startsWith("sk-")) return text.length <= 6 ? "***" : "***..." + text.slice(-4);
  if (text.length <= 4) return "*".repeat(text.length);
  if (text.length <= 8) return text.slice(0, 1) + "***" + text.slice(-1);
  return text.slice(0, 4) + "..." + text.slice(-4);
}

function sanitizeDisplayValue(value, keyName) {
  if (typeof value !== "string") return value;
  if (keyName && SENSITIVE_KEYS.has(normalizeSensitiveKey(keyName))) return maskSecretText(value);
  return value
    .replace(/\bBearer\s+([^\s,;]+)/gi, (_, token) => `Bearer ${maskSecretText(token)}`)
    .replace(/\bsk-[A-Za-z0-9._-]+\b/g, token => maskSecretText(token));
}

function sanitizeDisplayData(value, keyName) {
  if (Array.isArray(value)) return value.map(item => sanitizeDisplayData(item, keyName));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, sanitizeDisplayData(v, k)]));
  return sanitizeDisplayValue(value, keyName);
}

/* ── Key Management ───────────────────────────────── */

function isValidHash(s) {
  return /^[0-9a-f]{64}$/.test(s);
}

function loadKeysFromStorage() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) { state.keys = []; return; }
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) { state.keys = []; return; }
    // Migration: convert old format (raw key stored) to hash-only format
    const migrated = [];
    let needsSave = false;
    for (const k of parsed) {
      if (k.hash && isValidHash(k.hash)) {
        // Already new format
        migrated.push({ id: k.id, hash: k.hash, label: k.label || "", active: k.active !== false, count: k.count ?? null });
      } else if (k.key && typeof k.key === "string") {
        // Old format: has raw key, needs migration (async, will save after)
        needsSave = true;
        migrated.push({ id: k.id || generateId(), hash: null, label: k.label || "", active: k.active !== false, count: k.count ?? null, _rawKey: k.key });
      }
    }
    // Deduplicate by hash (safety: prevent ghost duplicates)
    const seen = new Set();
    state.keys = migrated.filter(k => {
      if (!k.hash) return true; // keep null-hash entries (pending migration)
      if (seen.has(k.hash)) return false;
      seen.add(k.hash);
      return true;
    });
    if (needsSave) migrateOldKeys();
  } catch { state.keys = []; }
}

async function migrateOldKeys() {
  let changed = false;
  for (const k of state.keys) {
    if (k._rawKey) {
      k.hash = await sha256(k._rawKey);
      delete k._rawKey;
      changed = true;
    }
  }
  if (changed) { saveKeysToStorage(); renderKeyList(); }
}

function saveKeysToStorage() {
  const data = state.keys.map(k => ({ id: k.id, hash: k.hash, label: k.label, active: k.active, count: k.count }));
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

function getActiveKeyHashes() {
  return state.keys.filter(k => k.active && k.hash).map(k => k.hash);
}

function maskHash(hash) {
  if (!hash) return "—";
  return hash.slice(0, 8) + "…" + hash.slice(-4);
}

const KEY_COLORS = [
  "#6366f1", "#22c55e", "#f59e0b", "#ef4444", "#a78bfa",
  "#22d3ee", "#ec4899", "#f97316", "#14b8a6", "#84cc16",
];

function keyColor(idx) {
  return KEY_COLORS[idx % KEY_COLORS.length];
}

function renderKeyList() {
  const list = document.getElementById("keyList");
  if (!state.keys.length) {
    list.innerHTML = '<div class="key-empty">暂未添加任何 API Key，在上方输入框添加后即可检索</div>';
  } else {
    list.innerHTML = state.keys.map((k, idx) => {
      const color = keyColor(idx);
      const displayName = k.label ? esc(k.label) : esc(maskHash(k.hash));
      const subtitle = k.label ? esc(maskHash(k.hash)) : '';
      const countText = k.count != null ? k.count + ' 条' : '';
      return `
      <div class="key-item ${k.active ? 'active' : 'inactive'}" data-kid="${k.id}" style="--key-color:${color}">
        <label class="key-check" onclick="event.stopPropagation()">
          <input type="checkbox" ${k.active ? 'checked' : ''} data-toggle="${k.id}" />
        </label>
        <span class="key-color-dot" style="background:${color}"></span>
        <span class="key-display-name" data-kid-name="${k.id}">${displayName}</span>
        ${subtitle ? `<span class="key-subtitle">${subtitle}</span>` : ''}
        ${countText ? `<span class="key-count">${countText}</span>` : ''}
        <button class="key-copy-btn" data-copy="${k.id}" title="复制 Key Hash">📋</button>
        <button class="key-edit-btn" data-edit="${k.id}" title="编辑别名">✎</button>
        <button class="key-del-btn" data-del="${k.id}" title="删除">✕</button>
      </div>`;
    }).join("");
  }
  document.getElementById("activeKeyCount").textContent = getActiveKeyHashes().length;
  updateKeySummary();
  updateMainVisibility();
}

function updateKeySummary() {
  const el = document.getElementById("keySummary");
  if (!el) return;
  const total = state.keys.length;
  const active = state.keys.filter(k => k.active).length;
  if (!total) {
    el.textContent = "未添加";
  } else if (active === total) {
    el.textContent = `全部 ${total} 个`;
  } else {
    el.textContent = `${active} / ${total} 已选`;
  }
}

function updateMainVisibility() {
  const hasActiveKeys = getActiveKeyHashes().length > 0;
  document.getElementById("noKeyOverlay").style.display = hasActiveKeys ? "none" : "";
  document.getElementById("mainArea").style.display = hasActiveKeys ? "" : "none";
}

async function verifyKeys() {
  const hashes = getActiveKeyHashes();
  if (!hashes.length) return;
  try {
    const resp = await fetch("/search/api/verify-keys", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key_hashes: hashes }),
    });
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.keys) {
      for (const k of state.keys) {
        if (k.hash && data.keys[k.hash]) {
          k.count = data.keys[k.hash].count;
        }
      }
      saveKeysToStorage();
      renderKeyList();
    }
  } catch (e) { console.error("verify keys error:", e); }
}

async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  // crypto.subtle is only available in secure contexts (HTTPS / localhost)
  if (typeof crypto !== "undefined" && crypto.subtle) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  // Fallback: pure-JS SHA-256 for non-secure contexts (HTTP)
  function rr(n,x){return(x>>>n)|(x<<(32-n));}
  const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  let H0=0x6a09e667,H1=0xbb67ae85,H2=0x3c6ef372,H3=0xa54ff53a,H4=0x510e527f,H5=0x9b05688c,H6=0x1f83d9ab,H7=0x5be0cd19;
  const l=data.length, bl=l*8;
  // Pre-processing: padding
  const padded=[...data,0x80];
  while(padded.length%64!==56) padded.push(0);
  // Append 64-bit big-endian bit length (high 32 bits always 0 for practical inputs)
  padded.push(0, 0, 0, 0);
  padded.push((bl >>> 24) & 0xff, (bl >>> 16) & 0xff, (bl >>> 8) & 0xff, bl & 0xff);
  // Process each 512-bit (64-byte) block
  for(let off=0;off<padded.length;off+=64){
    const W=new Array(64);
    for(let i=0;i<16;i++) W[i]=(padded[off+i*4]<<24)|(padded[off+i*4+1]<<16)|(padded[off+i*4+2]<<8)|padded[off+i*4+3];
    for(let i=16;i<64;i++){
      const s0=(rr(7,W[i-15])^rr(18,W[i-15])^(W[i-15]>>>3))>>>0;
      const s1=(rr(17,W[i-2])^rr(19,W[i-2])^(W[i-2]>>>10))>>>0;
      W[i]=(W[i-16]+s0+W[i-7]+s1)>>>0;
    }
    let a=H0,b=H1,c=H2,d=H3,e=H4,f=H5,g=H6,h=H7;
    for(let i=0;i<64;i++){
      const S1=(rr(6,e)^rr(11,e)^rr(25,e))>>>0;
      const ch=((e&f)^(~e&g))>>>0;
      const t1=(h+S1+ch+K[i]+W[i])>>>0;
      const S0=(rr(2,a)^rr(13,a)^rr(22,a))>>>0;
      const maj=((a&b)^(a&c)^(b&c))>>>0;
      const t2=(S0+maj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    H0=(H0+a)>>>0;H1=(H1+b)>>>0;H2=(H2+c)>>>0;H3=(H3+d)>>>0;H4=(H4+e)>>>0;H5=(H5+f)>>>0;H6=(H6+g)>>>0;H7=(H7+h)>>>0;
  }
  return [H0,H1,H2,H3,H4,H5,H6,H7].map(v=>v.toString(16).padStart(8,'0')).join('');
}

// Add key (raw key or hash depending on mode)
document.getElementById("addKeyBtn").addEventListener("click", async () => {
  const keyInput = document.getElementById("newKeyInput");
  const labelInput = document.getElementById("newKeyLabel");
  const raw = keyInput.value.trim();
  if (!raw) { keyInput.focus(); return; }

  let hash;
  if (state.inputMode === "hash") {
    // Direct hash input
    if (!isValidHash(raw.toLowerCase())) {
      alert("无效的 SHA-256 哈希（需要 64 位十六进制字符串）"); return;
    }
    hash = raw.toLowerCase();
  } else {
    // Raw key → hash client-side (strip "Bearer " prefix to match backend)
    let keyToHash = raw;
    if (keyToHash.toLowerCase().startsWith("bearer ")) {
      keyToHash = keyToHash.slice(7).trim();
    }
    hash = await sha256(keyToHash);
  }

  // Check duplicate
  if (state.keys.some(k => k.hash === hash)) {
    alert("该 Key（Hash）已存在"); return;
  }

  state.keys.push({
    id: generateId(),
    hash: hash,
    label: labelInput.value.trim(),
    active: true,
    count: null,
  });
  keyInput.value = "";
  labelInput.value = "";
  saveKeysToStorage();
  renderKeyList();
  verifyKeys().then(() => {
    if (getActiveKeyHashes().length > 0) loadLogs();
  });
});

document.getElementById("newKeyInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); document.getElementById("addKeyBtn").click(); }
});

// Checkbox toggle (via change event — immune to label stopPropagation)
document.getElementById("keyList").addEventListener("change", (e) => {
  const toggleCb = e.target.closest("[data-toggle]");
  if (toggleCb) {
    const kid = toggleCb.dataset.toggle;
    const k = state.keys.find(x => x.id === kid);
    if (k) { k.active = toggleCb.checked; saveKeysToStorage(); renderKeyList(); if (getActiveKeyHashes().length > 0) loadLogs(); }
  }
});

// Delete / Edit / Copy keys
document.getElementById("keyList").addEventListener("click", (e) => {
  // Copy hash
  const copyBtn = e.target.closest("[data-copy]");
  if (copyBtn) {
    const kid = copyBtn.dataset.copy;
    const k = state.keys.find(x => x.id === kid);
    if (k && k.hash) {
      _copyToClipboard(k.hash, copyBtn);
    }
    return;
  }
  // Edit alias
  const editBtn = e.target.closest("[data-edit]");
  if (editBtn) {
    startEditLabel(editBtn.dataset.edit);
    return;
  }
  // Delete
  const delBtn = e.target.closest("[data-del]");
  if (delBtn) {
    const kid = delBtn.dataset.del;
    const delKey = state.keys.find(x => x.id === kid);
    // Remove by ID, and also clean up any entries with the same hash (dedup safety)
    state.keys = state.keys.filter(x => x.id !== kid && !(delKey && delKey.hash && x.hash === delKey.hash));
    saveKeysToStorage();
    renderKeyList();
    if (getActiveKeyHashes().length > 0) loadLogs();
    return;
  }
  // Click on card body to toggle
  const card = e.target.closest(".key-item");
  if (card && !e.target.closest("input, button, label, .key-edit-inline")) {
    const kid = card.dataset.kid;
    const k = state.keys.find(x => x.id === kid);
    if (k) { k.active = !k.active; saveKeysToStorage(); renderKeyList(); if (getActiveKeyHashes().length > 0) loadLogs(); }
  }
});

// Inline label editing
function startEditLabel(kid) {
  const k = state.keys.find(x => x.id === kid);
  if (!k) return;
  const nameSpan = document.querySelector(`[data-kid-name="${kid}"]`);
  if (!nameSpan) return;
  const currentLabel = k.label || "";
  const input = document.createElement("input");
  input.type = "text";
  input.className = "key-edit-inline";
  input.value = currentLabel;
  input.placeholder = "输入别名…";
  nameSpan.replaceWith(input);
  input.focus();
  input.select();
  const commit = () => {
    k.label = input.value.trim();
    saveKeysToStorage();
    renderKeyList();
  };
  input.addEventListener("blur", commit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); input.blur(); }
    if (e.key === "Escape") { input.value = currentLabel; input.blur(); }
  });
}

document.getElementById("selectAllKeys").addEventListener("click", () => {
  state.keys.forEach(k => k.active = true);
  saveKeysToStorage(); renderKeyList();
  if (getActiveKeyHashes().length > 0) loadLogs();
});

document.getElementById("deselectAllKeys").addEventListener("click", () => {
  state.keys.forEach(k => k.active = false);
  saveKeysToStorage(); renderKeyList();
});

// Input mode toggle
document.getElementById("modeKeyBtn").addEventListener("click", () => {
  state.inputMode = "key";
  document.getElementById("modeKeyBtn").classList.add("active");
  document.getElementById("modeHashBtn").classList.remove("active");
  document.getElementById("newKeyInput").placeholder = "输入 API Key（如 sk-xxxxx）";
});

document.getElementById("modeHashBtn").addEventListener("click", () => {
  state.inputMode = "hash";
  document.getElementById("modeHashBtn").classList.add("active");
  document.getElementById("modeKeyBtn").classList.remove("active");
  document.getElementById("newKeyInput").placeholder = "输入 SHA-256 Hash（64 位十六进制）";
});

// Clear all local data
document.getElementById("clearAllData").addEventListener("click", () => {
  if (!confirm("确定要清除所有本地存储的 Key 数据？此操作不可恢复。")) return;
  localStorage.removeItem(STORAGE_KEY);
  state.keys = [];
  renderKeyList();
});

// Toggle add-key panel
document.getElementById("addKeyToggle").addEventListener("click", () => {
  const panel = document.getElementById("keyAddPanel");
  const visible = panel.style.display !== "none";
  panel.style.display = visible ? "none" : "flex";
  if (!visible) document.getElementById("newKeyInput").focus();
});

/* ── API calls ────────────────────────────────────── */

async function fetchSearchAPI(url, body) {
  body.key_hashes = getActiveKeyHashes();
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const t = await r.text();
    let detail;
    try { detail = JSON.parse(t).detail; } catch { detail = t.slice(0, 200); }
    throw new Error(detail || "请求失败: " + r.status);
  }
  return r.json();
}

/* ── Log list ─────────────────────────────────────── */

async function loadLogs() {
  const activeHashes = getActiveKeyHashes();
  if (!activeHashes.length) return;

  const body = {
    ...state.filters,
    path_contains: state.pathFilter,
    page: state.page,
    page_size: state.pageSize,
  };

  try {
    const p = await fetchSearchAPI("/search/api/logs", body);
    const { items, pagination } = p;
    state.pages = pagination.pages;

    document.getElementById("pageInfo").textContent = `${pagination.page} / ${pagination.pages}`;
    document.getElementById("logMeta").textContent = `${pagination.total} 条记录`;
    document.getElementById("totalRecords").textContent = pagination.total;
    document.getElementById("prevPage").disabled = pagination.page <= 1;
    document.getElementById("nextPage").disabled = pagination.page >= pagination.pages;

    const list = document.getElementById("traceList");
    if (!items.length) {
      list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted)">无记录</div>';
      return;
    }

    list.innerHTML = items.map(i => {
      const methodCls = i.method === "POST" ? "post" : i.method === "GET" ? "get" : "";
      const statusCls = (i.response_status >= 400) ? "err" : "ok";
      const active = (i.id === state.selectedTraceId) ? " active" : "";
      const stream = i.request_stream ? '<span class="tc-stream">⚡</span>' : "";
      const cost = i.estimated_cost ? `<span class="tc-cost">${fmtCost(i.estimated_cost)}</span>` : "";
      const preview = sanitizeDisplayValue(i.preview || "", "preview");
      const fpBadge = i.conv_fingerprint
        ? `<span class="tc-conv" data-fp="${esc(i.conv_fingerprint)}" title="会话 ${esc(i.conv_fingerprint)}" style="--fp-color:${fpColor(i.conv_fingerprint)}" onclick="event.stopPropagation();filterConversation('${esc(i.conv_fingerprint)}')"><span class="tc-conv-dot"></span>${i.msg_count || 0}msg</span>`
        : "";
      return `
        <div class="trace-card${active}" data-id="${i.id}">
          <div class="tc-row1">
            <span class="tc-method ${methodCls}">${esc(i.method)}</span>
            <span class="tc-model">${esc(i.request_model || i.path)}</span>
            ${stream}
            ${fpBadge}
            ${cost}
            <span class="tc-status ${statusCls}">${i.response_status ?? "-"}</span>
          </div>
          <div class="tc-row2">
            <span class="tc-time">${fmtTime(i.created_at)}</span>
            <span class="tc-dur">${fmtMs(i.duration_ms)}</span>
            <span class="tc-preview">${esc(preview)}</span>
          </div>
        </div>`;
    }).join("");
  } catch (err) {
    console.error("loadLogs error:", err);
  }
}

function filterConversation(fp) {
  state.filters.conv_fingerprint = fp;
  state.page = 1;
  const fpInput = document.querySelector('#searchForm input[name="conv_fingerprint"]');
  if (fpInput) fpInput.value = fp;
  document.getElementById("advancedFilters").style.display = "";
  loadLogs();
}

/* ── Detail ───────────────────────────────────────── */

async function loadDetail(id) {
  try {
    const entry = await fetchSearchAPI(`/search/api/logs/${id}`, {});
    state.detailEntry = entry;
    renderDetail(entry);
  } catch (err) {
    document.getElementById("detailPane").innerHTML = `<div style="padding:20px;color:var(--text-muted)">${esc(err.message)}</div>`;
  }
}

/* ── JSON highlighting ────────────────────────────── */

function highlightJSON(obj, indent, keyName) {
  indent = indent || 0;
  const pad = "  ".repeat(indent);
  if (obj === null) return '<span class="jnull">null</span>';
  if (typeof obj === "boolean") return `<span class="jb">${obj}</span>`;
  if (typeof obj === "number") return `<span class="jn">${obj}</span>`;
  if (typeof obj === "string") {
    const s = JSON.stringify(sanitizeDisplayValue(obj, keyName));
    if (s.length > 500) return `<span class="js">${esc(s.slice(0, 400))}</span><span class="jnull">…(${s.length} chars)</span><span class="js">${esc(s.slice(-50))}</span>`;
    return `<span class="js">${esc(s)}</span>`;
  }
  if (Array.isArray(obj)) {
    if (!obj.length) return '<span class="jpunc">[]</span>';
    const items = obj.map(v => pad + "  " + highlightJSON(v, indent + 1, keyName));
    return '<span class="jpunc">[</span>\n' + items.join(',\n') + '\n' + pad + '<span class="jpunc">]</span>';
  }
  if (typeof obj === "object") {
    const keys = Object.keys(obj);
    if (!keys.length) return '<span class="jpunc">{}</span>';
    const entries = keys.map(k => pad + '  <span class="jk">' + esc(JSON.stringify(k)) + '</span><span class="jpunc">: </span>' + highlightJSON(obj[k], indent + 1, k));
    return '<span class="jpunc">{</span>\n' + entries.join(',\n') + '\n' + pad + '<span class="jpunc">}</span>';
  }
  return esc(String(obj));
}

/* ── SSE parse ────────────────────────────────────── */

function parseSSE(raw) {
  if (typeof raw !== "string") return null;
  let reasoning = "", content = "", model = "", finish = "";
  let usage = null, toolCalls = [];
  for (const ln of raw.split("\n")) {
    if (!ln.startsWith("data: ")) continue;
    const payload = ln.slice(6).trim();
    if (payload === "[DONE]") continue;
    try {
      const c = JSON.parse(payload);
      if (c.model) model = c.model;
      if (c.usage) usage = c.usage;
      for (const ch of (c.choices || [])) {
        if (ch.finish_reason) finish = ch.finish_reason;
        const d = ch.delta || {};
        if (d.reasoning_content) reasoning += d.reasoning_content;
        if (d.content) content += d.content;
        if (d.tool_calls) {
          for (const tc of d.tool_calls) {
            const idx = tc.index ?? toolCalls.length;
            if (!toolCalls[idx]) toolCalls[idx] = { id:"", type:"function", function:{ name:"", arguments:"" } };
            if (tc.id) toolCalls[idx].id = tc.id;
            if (tc.function) {
              if (tc.function.name) toolCalls[idx].function.name += tc.function.name;
              if (tc.function.arguments) toolCalls[idx].function.arguments += tc.function.arguments;
            }
          }
        }
      }
    } catch {}
  }
  const filtered = toolCalls.filter(Boolean);
  return { reasoning, content, model, finish, usage, toolCalls: filtered.length ? filtered : null };
}

function extractResponse(entry) {
  const rb = entry.response_body;
  if (rb && typeof rb === "object") {
    const ch = (rb.choices || [])[0];
    const m = ch?.message || {};
    return { reasoning: m.reasoning_content || "", content: m.content || "", model: rb.model || "", finish: ch?.finish_reason || "", usage: rb.usage || null, toolCalls: m.tool_calls || null };
  }
  if (typeof rb === "string") return parseSSE(rb);
  return null;
}

/* ── Token estimation helpers ─────────────────────── */

function estimateTokenCount(text) {
  if (!text) return 0;
  const s = String(text);
  const cjkChars = (s.match(/[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]/g) || []).length;
  const cjkPunct = (s.match(/[\u3000-\u303f\uff01-\uff60\ufe30-\ufe4f\u2018-\u201f\u2026\u2014]/g) || []).length;
  const enWords = s.match(/[a-zA-Z]+/g) || [];
  const enLetters = enWords.reduce((n, w) => n + w.length, 0);
  const digitSeqs = s.match(/\d+/g) || [];
  const digitChars = digitSeqs.reduce((n, d) => n + d.length, 0);
  const wsChars = (s.match(/\s/g) || []).length;
  const otherChars = Math.max(0, s.length - cjkChars - cjkPunct - enLetters - digitChars - wsChars);
  const tokens = cjkChars * 0.7 + cjkPunct * 1.0 + enWords.length * 1.3 + digitChars / 3.3 + wsChars * 0.15 + otherChars * 1.0;
  return Math.max(1, Math.round(tokens));
}

function collectContentText(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(collectContentText).join("\n");
  if (typeof value === "object") {
    if (typeof value.text === "string") return value.text;
    if (typeof value.content === "string") return value.content;
    if (Array.isArray(value.content)) return value.content.map(collectContentText).join("\n");
    return Object.values(value).map(collectContentText).join("\n");
  }
  return String(value);
}

function estimateUsage(entry, resp) {
  const requestBody = entry?.request_body;
  const roleMap = {};
  const addRole = (role, text) => {
    if (!text) return;
    if (!roleMap[role]) roleMap[role] = { text: "", chars: 0, tokens: 0 };
    roleMap[role].text += text + "\n";
  };
  if (requestBody && typeof requestBody === "object") {
    if (typeof requestBody.prompt === "string") addRole("user", requestBody.prompt);
    if (typeof requestBody.input === "string") addRole("user", requestBody.input);
    if (Array.isArray(requestBody.messages)) {
      requestBody.messages.forEach(msg => {
        const role = (msg?.role || "user").toLowerCase();
        const text = collectContentText(msg?.content);
        if (Array.isArray(msg?.tool_calls)) {
          const tcText = msg.tool_calls.map(tc => (tc?.function?.name || "") + " " + (tc?.function?.arguments || "")).join("\n");
          addRole("assistant", tcText);
        }
        addRole(role, text);
      });
    }
    if (Array.isArray(requestBody.tools)) addRole("tools_schema", JSON.stringify(requestBody.tools));
    else if (Array.isArray(requestBody.functions)) addRole("tools_schema", JSON.stringify(requestBody.functions));
  }
  const responseParts = [];
  if (resp?.content) responseParts.push(resp.content);
  if (resp?.reasoning) responseParts.push(resp.reasoning);
  if (Array.isArray(resp?.toolCalls)) resp.toolCalls.forEach(tc => responseParts.push((tc?.function?.name || "") + " " + (tc?.function?.arguments || "")));
  const completionText = responseParts.filter(Boolean).join("\n");
  let promptTokens = 0;
  const roleBreakdown = [];
  for (const [role, info] of Object.entries(roleMap)) {
    info.chars = info.text.length;
    info.tokens = estimateTokenCount(info.text);
    promptTokens += info.tokens;
    roleBreakdown.push({ role, tokens: info.tokens, chars: info.chars });
  }
  const completionTokens = estimateTokenCount(completionText);
  if (!promptTokens && !completionTokens) return null;
  return { prompt_tokens: promptTokens, completion_tokens: completionTokens, total_tokens: promptTokens + completionTokens, estimated: true, role_breakdown: roleBreakdown };
}

/* ── Token panel / params rendering ───────────────── */

const ROLE_META = {
  system:       { label: "System",     cls: "role-system" },
  user:         { label: "User",       cls: "role-user" },
  assistant:    { label: "Assistant",  cls: "role-assistant" },
  developer:    { label: "Developer",  cls: "role-system" },
  tool:         { label: "Tool 结果",  cls: "role-tool" },
  tools_schema: { label: "Tools 定义", cls: "role-tools-schema" },
  function:     { label: "Function",   cls: "role-function" },
};
function roleMeta(role) {
  return ROLE_META[role] || { label: role, cls: "role-other" };
}

function renderTokenPanel(usage, entry, resp) {
  const effectiveUsage = usage || estimateUsage(entry, resp);
  if (!effectiveUsage) return "";
  const prompt = effectiveUsage.prompt_tokens ?? 0;
  const compl = effectiveUsage.completion_tokens ?? 0;
  const total = effectiveUsage.total_tokens || (prompt + compl);
  const promptDetails = effectiveUsage.prompt_tokens_details || {};
  const complDetails = effectiveUsage.completion_tokens_details || {};
  const reasoning = complDetails.reasoning_tokens ?? 0;
  const cached = promptDetails.cached_tokens ?? 0;
  const audioPrompt = promptDetails.audio_tokens ?? 0;
  const audioCompl = complDetails.audio_tokens ?? 0;
  const acceptedPrediction = complDetails.accepted_prediction_tokens ?? 0;
  const rejectedPrediction = complDetails.rejected_prediction_tokens ?? 0;
  const actualPrompt = prompt - cached - audioPrompt;
  const actualCompl = compl - reasoning - audioCompl - acceptedPrediction - rejectedPrediction;

  const analysis = entry?.token_analysis;
  let breakdown = null;
  let complBreakdown = null;
  if (analysis) {
    breakdown = analysis.prompt_breakdown;
    complBreakdown = analysis.completion_breakdown;
  } else {
    breakdown = effectiveUsage.role_breakdown;
    if (!breakdown && !effectiveUsage.estimated) {
      const estimated = estimateUsage(entry, resp);
      if (estimated && estimated.role_breakdown && estimated.role_breakdown.length > 0) {
        const estTotal = estimated.role_breakdown.reduce((s, r) => s + r.tokens, 0) || 1;
        breakdown = estimated.role_breakdown.map(r => ({ role: r.role, tokens: Math.round(r.tokens / estTotal * prompt), chars: r.chars, scaled: true }));
      }
    }
  }

  // Main bar
  const segs = [];
  if (total > 0) {
    if (cached > 0) segs.push({ c: "cached", p: cached/total*100, l: `缓存 ${cached}` });
    if (actualPrompt > 0) segs.push({ c: "prompt", p: actualPrompt/total*100, l: `Prompt ${actualPrompt}` });
    if (audioPrompt > 0) segs.push({ c: "audio-prompt", p: audioPrompt/total*100, l: `音频输入 ${audioPrompt}` });
    if (reasoning > 0) segs.push({ c: "reasoning", p: reasoning/total*100, l: `推理 ${reasoning}` });
    if (actualCompl > 0) segs.push({ c: "completion", p: actualCompl/total*100, l: `输出 ${actualCompl}` });
    if (audioCompl > 0) segs.push({ c: "audio-compl", p: audioCompl/total*100, l: `音频输出 ${audioCompl}` });
    if (acceptedPrediction > 0) segs.push({ c: "accepted-pred", p: acceptedPrediction/total*100, l: `预测命中 ${acceptedPrediction}` });
    if (rejectedPrediction > 0) segs.push({ c: "rejected-pred", p: rejectedPrediction/total*100, l: `预测未命中 ${rejectedPrediction}` });
  }
  const bar = segs.map(s =>
    `<div class="tbar-seg ${s.c}" style="width:${Math.max(s.p,2).toFixed(1)}%" title="${s.l}">${s.p > 12 ? s.l : ""}</div>`
  ).join("");

  // Summary stats
  const items = [];
  items.push(tsItem("prompt", "Prompt", prompt));
  if (cached > 0) items.push(tsItem("cached", "缓存命中", cached));
  if (audioPrompt > 0) items.push(tsItem("audio-prompt", "音频输入", audioPrompt));
  items.push(tsItem("completion", "Completion", compl));
  if (reasoning > 0) items.push(tsItem("reasoning", "推理", reasoning));
  if (audioCompl > 0) items.push(tsItem("audio-compl", "音频输出", audioCompl));
  if (acceptedPrediction > 0) items.push(tsItem("accepted-pred", "预测命中", acceptedPrediction));
  if (rejectedPrediction > 0) items.push(tsItem("rejected-pred", "预测未命中", rejectedPrediction));
  items.push(`<div class="ts-item"><strong style="font-size:14px">总计 ${total}</strong></div>`);
  if (cached > 0 && prompt > 0) items.push(`<div class="ts-item">缓存率<strong>${((cached/prompt)*100).toFixed(1)}%</strong></div>`);

  // Prompt breakdown
  let roleHtml = "";
  if (breakdown && breakdown.length > 0) {
    const sorted = [...breakdown].sort((a, b) => b.tokens - a.tokens);
    const roleTotal = sorted.reduce((s, r) => s + r.tokens, 0) || 1;
    const isScaled = sorted.some(r => r.scaled);
    const roleBar = sorted.map(r => {
      const m = roleMeta(r.role);
      const pct = r.tokens / roleTotal * 100;
      return `<div class="tbar-seg ${m.cls}" style="width:${Math.max(pct,2).toFixed(1)}%" title="${m.label} ${r.tokens}">${pct > 10 ? m.label + " " + r.tokens : ""}</div>`;
    }).join("");
    const roleRows = sorted.map(r => {
      const m = roleMeta(r.role);
      const pct = (r.tokens / roleTotal * 100).toFixed(1);
      const charsInfo = r.chars != null ? `<span class="ts-chars">${r.chars} 字符</span>` : "";
      const countInfo = r.count != null && r.count > 0 ? `<span class="ts-count">${r.count} 条</span>` : "";
      return `<div class="ts-item"><span class="ts-dot ${m.cls}"></span>${m.label}<strong>${r.tokens}</strong><span class="ts-pct">${pct}%</span>${charsInfo}${countInfo}</div>`;
    }).join("");
    const breakdownTitle = isScaled ? "Prompt 构成明细（按比例估算）" : "Prompt 构成明细";
    roleHtml = `<div class="role-breakdown"><div class="role-breakdown-title">${breakdownTitle}</div><div class="token-bar">${roleBar}</div><div class="token-stats">${roleRows}</div></div>`;
  }

  // Completion breakdown
  let complHtml = "";
  if (complBreakdown && complBreakdown.length > 1) {
    const sorted = [...complBreakdown].sort((a, b) => b.tokens - a.tokens);
    const complTotal = sorted.reduce((s, r) => s + r.tokens, 0) || 1;
    const clsMap = { text_output: "completion", reasoning: "reasoning", tool_calls: "tool-calls", audio: "audio-compl" };
    const complBar = sorted.map(r => {
      const cls = clsMap[r.category] || "completion";
      const pct = r.tokens / complTotal * 100;
      return `<div class="tbar-seg ${cls}" style="width:${Math.max(pct,2).toFixed(1)}%" title="${r.label} ${r.tokens}">${pct > 10 ? r.label + " " + r.tokens : ""}</div>`;
    }).join("");
    const complRows = sorted.map(r => {
      const cls = clsMap[r.category] || "completion";
      const pct = (r.tokens / complTotal * 100).toFixed(1);
      const charsInfo = r.chars != null ? `<span class="ts-chars">${r.chars} 字符</span>` : "";
      return `<div class="ts-item"><span class="ts-dot ${cls}"></span>${r.label}<strong>${r.tokens}</strong><span class="ts-pct">${pct}%</span>${charsInfo}</div>`;
    }).join("");
    complHtml = `<div class="role-breakdown"><div class="role-breakdown-title">Completion 构成明细</div><div class="token-bar">${complBar}</div><div class="token-stats">${complRows}</div></div>`;
  } else if (compl > 0 && (reasoning > 0 || audioCompl > 0 || acceptedPrediction > 0 || rejectedPrediction > 0)) {
    const complSegs = [];
    const actualOutput = compl - reasoning - audioCompl - acceptedPrediction - rejectedPrediction;
    if (actualOutput > 0) complSegs.push({ cls: "completion", tokens: actualOutput, label: "文本输出" });
    if (reasoning > 0) complSegs.push({ cls: "reasoning", tokens: reasoning, label: "推理" });
    if (audioCompl > 0) complSegs.push({ cls: "audio-compl", tokens: audioCompl, label: "音频输出" });
    if (acceptedPrediction > 0) complSegs.push({ cls: "accepted-pred", tokens: acceptedPrediction, label: "预测命中" });
    if (rejectedPrediction > 0) complSegs.push({ cls: "rejected-pred", tokens: rejectedPrediction, label: "预测未命中" });
    const complTotal = complSegs.reduce((s, r) => s + r.tokens, 0) || 1;
    const complBar = complSegs.map(r => {
      const pct = r.tokens / complTotal * 100;
      return `<div class="tbar-seg ${r.cls}" style="width:${Math.max(pct,2).toFixed(1)}%" title="${r.label} ${r.tokens}">${pct > 10 ? r.label + " " + r.tokens : ""}</div>`;
    }).join("");
    const complRows = complSegs.map(r => {
      const pct = (r.tokens / complTotal * 100).toFixed(1);
      return `<div class="ts-item"><span class="ts-dot ${r.cls}"></span>${r.label}<strong>${r.tokens}</strong><span class="ts-pct">${pct}%</span></div>`;
    }).join("");
    complHtml = `<div class="role-breakdown"><div class="role-breakdown-title">Completion 构成明细</div><div class="token-bar">${complBar}</div><div class="token-stats">${complRows}</div></div>`;
  }

  const note = effectiveUsage.estimated
    ? '<div class="token-note">当前记录未返回官方 usage，以上为基于 CJK 0.7t/字 + EN 1.3t/词 的近似估算。</div>'
    : "";
  const scaleNote = (analysis && analysis.has_real_usage === false) ? '<div class="token-note">构成明细基于字符比例估算，总量为近似值。</div>' : "";
  const title = effectiveUsage.estimated ? "Token 用量（估算）" : "Token 用量";
  return `<div class="token-panel"><h4>${title}</h4><div class="token-bar">${bar}</div><div class="token-stats">${items.join("")}</div>${roleHtml}${complHtml}${note}${scaleNote}</div>`;
}

function tsItem(cls, label, val) {
  return `<div class="ts-item"><span class="ts-dot ${cls}"></span>${label}<strong>${val}</strong></div>`;
}

function renderParamsSection(body) {
  if (!body || typeof body !== "object") return "";
  const skip = new Set(["messages","tools","functions","tool_choice","function_call"]);
  const params = Object.entries(body).filter(([k]) => !skip.has(k));
  if (!params.length) return "";
  return '<div class="params-section">' + params.map(([k, v]) => {
    let display = v;
    if (typeof v === "object" && v !== null) display = JSON.stringify(v);
    display = sanitizeDisplayValue(String(display), k);
    return `<div class="param-chip"><div class="pk">${esc(k)}</div><div class="pv">${esc(String(display))}</div><div class="pv-toggle">展开 ▼</div></div>`;
  }).join("") + '</div>';
}

/* ── Detail rendering ─────────────────────────────── */

function renderDetail(entry) {
  const pane = document.getElementById("detailPane");
  const resp = extractResponse(entry);
  const reqBody = entry.request_body;
  const messages = (reqBody && typeof reqBody === "object") ? reqBody.messages : null;
  const tools = (reqBody && typeof reqBody === "object") ? (reqBody.tools || reqBody.functions) : null;
  const usage = resp?.usage || null;
  const statusCls = (entry.response_status >= 400) ? "err" : "ok";
  const model = reqBody?.model || resp?.model || "-";

  const msgCount = messages ? messages.length : 0;
  const toolCount = tools ? tools.length : 0;
  const respToolCount = resp?.toolCalls ? resp.toolCalls.length : 0;

  let html = `
    <div class="detail-header">
      <div class="detail-title-row">
        <h3>${esc(model)}</h3>
        <span class="tc-method ${entry.method === "POST" ? "post" : "get"}" style="font-size:11px">${esc(entry.method)}</span>
        <span class="tc-status ${statusCls}" style="font-size:12px">${entry.response_status ?? "-"}</span>
        ${reqBody?.stream ? '<span class="tc-stream">⚡ Stream</span>' : ""}
      </div>
      <div class="detail-meta-grid">
        <div class="dm-item"><span class="dm-label">耗时</span><span class="dm-value">${fmtMs(entry.duration_ms)}</span></div>
        <div class="dm-item"><span class="dm-label">时间</span><span class="dm-value">${fmtTimeFull(entry.timestamp)}</span></div>
        ${usage ? `<div class="dm-item"><span class="dm-label">Tokens</span><span class="dm-value">${usage.total_tokens ?? (usage.prompt_tokens || 0) + (usage.completion_tokens || 0)}</span></div>` : ""}
        ${entry.estimated_cost ? `<div class="dm-item"><span class="dm-label">成本</span><span class="dm-value cost-value">${fmtCost(entry.estimated_cost)}</span></div>` : ""}
        ${entry.conv_fingerprint ? `<div class="dm-item"><span class="dm-label">会话</span><span class="dm-value"><span class="tc-conv" style="--fp-color:${fpColor(entry.conv_fingerprint)};cursor:pointer" onclick="filterConversation('${esc(entry.conv_fingerprint)}')"><span class="tc-conv-dot"></span>${esc(entry.conv_fingerprint)}</span></span></div>` : ""}
      </div>
      <div class="detail-tabs">
        <button class="tab-btn active" data-tab="friendly">友好视图</button>
        <button class="tab-btn" data-tab="messages">消息 <span class="tab-badge">${msgCount}</span></button>
        ${toolCount ? `<button class="tab-btn" data-tab="tools">工具 <span class="tab-badge">${toolCount}</span></button>` : ""}
        <button class="tab-btn" data-tab="response">回复${respToolCount ? ` <span class="tab-badge">${respToolCount} calls</span>` : ""}</button>
        ${entry.conv_fingerprint ? '<button class="tab-btn" data-tab="timeline">会话时间线</button>' : ""}
        <button class="tab-btn" data-tab="raw">JSON</button>
      </div>
    </div>
    <div class="detail-body">
  `;

  // ── Tab: Friendly ──
  html += '<div class="tab-panel active" data-panel="friendly">';
  html += renderTokenPanel(usage, entry, resp);
  html += renderParamsSection(reqBody);
  if (messages && messages.length) {
    html += '<div style="margin-bottom:16px"><h4 style="font-size:13px;color:var(--text-secondary);margin-bottom:8px">消息线程</h4>';
    html += renderMsgThread(messages);
    html += '</div>';
  }
  html += renderResponseBlock(resp);
  html += '</div>';

  // ── Tab: Messages ──
  html += '<div class="tab-panel" data-panel="messages">';
  if (messages && messages.length) {
    html += renderMsgThread(messages);
  } else {
    html += '<div style="color:var(--text-muted)">无消息数据</div>';
  }
  html += renderResponseBlock(resp);
  html += '</div>';

  // ── Tab: Tools ──
  if (toolCount) {
    html += '<div class="tab-panel" data-panel="tools">';
    html += renderToolsDef(tools);
    html += '</div>';
  }

  // ── Tab: Response ──
  html += '<div class="tab-panel" data-panel="response">';
  html += renderResponseBlock(resp);
  html += '</div>';

  // ── Tab: Timeline ──
  if (entry.conv_fingerprint) {
    html += `<div class="tab-panel" data-panel="timeline"><div id="timelineContent"><div style="color:var(--text-muted);padding:20px">加载中…</div></div></div>`;
  }

  // ── Tab: Raw ──
  html += '<div class="tab-panel" data-panel="raw">';
  html += '<div class="json-view">' + highlightJSON(entry) + '</div>';
  html += '</div>';

  html += '</div>';

  pane.innerHTML = html;
  pane.className = "";

  // Detect truncated param chips and add expand/collapse
  pane.querySelectorAll(".param-chip").forEach(chip => {
    const pv = chip.querySelector(".pv");
    if (pv && pv.scrollHeight > pv.clientHeight + 2) {
      chip.classList.add("truncated");
      chip.querySelector(".pv-toggle")?.addEventListener("click", () => {
        chip.classList.toggle("expanded");
        chip.querySelector(".pv-toggle").textContent = chip.classList.contains("expanded") ? "收起 ▲" : "展开 ▼";
      });
    }
  });

  pane.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      pane.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      pane.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      pane.querySelector(`[data-panel="${btn.dataset.tab}"]`).classList.add("active");
      if (btn.dataset.tab === "timeline" && entry.conv_fingerprint) {
        loadTimeline(entry.conv_fingerprint, entry.id);
      }
    });
  });
}

/* ── Timeline ─────────────────────────────────────── */

async function loadTimeline(fp, currentId) {
  const wrap = document.getElementById("timelineContent");
  if (!wrap) return;
  try {
    const data = await fetchSearchAPI(`/search/api/conversation/${encodeURIComponent(fp)}`, {});
    const items = data.items || [];
    if (!items.length) {
      wrap.innerHTML = '<div style="color:var(--text-muted);padding:16px">无关联请求</div>';
      return;
    }
    let html = `<div class="conv-timeline-header"><span class="conv-fp" style="--fp-color:${fpColor(fp)}"><span class="tc-conv-dot"></span>会话 ${esc(fp)}</span><span class="conv-count">${items.length} 个请求</span></div>`;
    html += '<div class="conv-timeline">';
    items.forEach((item, idx) => {
      const isCurrent = item.id === currentId;
      const statusCls = (item.response_status >= 400) ? "err" : "ok";
      html += `
        <div class="conv-tl-item${isCurrent ? ' current' : ''}" data-tl-id="${item.id}">
          <div class="conv-tl-content">
            <div class="conv-tl-row1">
              <span class="conv-tl-idx">#${idx + 1}</span>
              <span class="conv-tl-model">${esc(item.request_model || item.path)}</span>
              <span class="conv-tl-msgs">${item.msg_count || 0} msg</span>
              <span class="tc-status ${statusCls}" style="font-size:11px">${item.response_status ?? "-"}</span>
            </div>
            <div class="conv-tl-row2">
              <span>${fmtTime(item.created_at)}</span>
              <span>${fmtMs(item.duration_ms)}</span>
            </div>
            <div class="conv-tl-preview">${esc(sanitizeDisplayValue(item.preview || "", "preview"))}</div>
          </div>
        </div>`;
    });
    html += '</div>';
    wrap.innerHTML = html;
    wrap.querySelectorAll("[data-tl-id]").forEach(el => {
      el.addEventListener("click", () => {
        state.selectedTraceId = el.dataset.tlId;
        loadDetail(el.dataset.tlId);
      });
    });
  } catch (err) {
    wrap.innerHTML = `<div style="color:var(--text-muted);padding:16px">加载失败: ${esc(err.message)}</div>`;
  }
}

/* ── Message thread rendering ─────────────────────── */

function renderMsgThread(messages) {
  let html = '<div class="msg-thread">';
  for (let i = 0; i < messages.length; i++) {
    html += renderMsgBubble(messages[i], i, messages.length, i === 0 || i === messages.length - 1);
  }
  html += '</div>';
  return html;
}

function renderMsgBubble(msg, idx, total, open) {
  const role = msg.role || "unknown";
  const collapsed = open ? "" : " collapsed";
  let bodyHtml = "";
  let meta = "";

  const content = msg.content;
  if (typeof content === "string") {
    meta = `${content.length} 字符`;
    bodyHtml = `<div class="msg-content">${esc(sanitizeDisplayValue(content, "content"))}</div>`;
  } else if (Array.isArray(content)) {
    meta = `${content.length} 部分`;
    const parts = content.map(p => {
      if (p.type === "text") return `<div style="white-space:pre-wrap">${esc(sanitizeDisplayValue(p.text || "", "text"))}</div>`;
      if (p.type === "image_url") return `<div style="color:var(--text-muted)">[图片]</div>`;
      return `<div><pre style="margin:0">${esc(JSON.stringify(sanitizeDisplayData(p), null, 2))}</pre></div>`;
    }).join("");
    bodyHtml = `<div class="msg-content">${parts}</div>`;
  } else if (content == null) {
    if (msg.tool_calls) {
      meta = `${msg.tool_calls.length} 个工具调用`;
      bodyHtml = '<div class="msg-content">' + msg.tool_calls.map(tc => {
        const fn = tc.function || {};
        let args = fn.arguments || "";
        try { args = JSON.stringify(sanitizeDisplayData(JSON.parse(args)), null, 2); } catch { args = sanitizeDisplayValue(args, "arguments"); }
        return `<div class="tool-card"><div class="tool-card-head" onclick="event.stopPropagation();this.parentElement.classList.toggle('closed')"><span class="tool-icon">⚙</span><span class="tool-fname">${esc(fn.name || "")}</span></div><div class="tool-card-body"><pre>${esc(args)}</pre></div></div>`;
      }).join("") + '</div>';
    } else {
      bodyHtml = '<div class="msg-content" style="color:var(--text-muted)">（空）</div>';
    }
  } else {
    bodyHtml = `<div class="msg-content"><pre style="margin:0">${esc(JSON.stringify(sanitizeDisplayData(content), null, 2))}</pre></div>`;
  }

  return `
    <div class="msg-bubble${collapsed}">
      <div class="msg-bubble-head" onclick="this.parentElement.classList.toggle('collapsed')">
        <span class="msg-role-tag ${role}">${role}</span>
        <span class="msg-info">#${idx + 1} ${meta ? "· " + meta : ""}</span>
        <span class="msg-arrow">▼</span>
      </div>
      ${bodyHtml}
    </div>`;
}

/* ── Tools definition ─────────────────────────────── */

function renderToolsDef(tools) {
  if (!tools || !tools.length) return "";
  return '<div class="tool-grid">' + tools.map(t => {
    const fn = t.function || t;
    const name = fn.name || "(unnamed)";
    const desc = fn.description || "";
    const params = fn.parameters;
    let bodyHtml = "";
    if (params && params.properties) {
      const required = new Set(params.required || []);
      const rows = Object.entries(params.properties).map(([pname, pdef]) =>
        `<tr><td class="pname">${esc(pname)} ${required.has(pname) ? '<span class="preq">必需</span>' : ""}</td><td class="ptype">${esc(pdef.type || "")}</td><td class="pdesc">${esc(pdef.description || "")}</td></tr>`
      ).join("");
      bodyHtml = `<table class="tool-param-table"><thead><tr><th>参数</th><th>类型</th><th>说明</th></tr></thead><tbody>${rows}</tbody></table>`;
    }
    return `<div class="tool-card closed" onclick="this.classList.toggle('closed')"><div class="tool-card-head"><span class="tool-icon">⚙</span><span class="tool-fname">${esc(name)}</span><span class="tool-desc-text">${esc(desc.slice(0, 100))}</span></div>${bodyHtml ? `<div class="tool-card-body">${bodyHtml}</div>` : ""}</div>`;
  }).join("") + '</div>';
}

/* ── Response block ───────────────────────────────── */

function renderResponseBlock(resp) {
  if (!resp) return '<div style="color:var(--text-muted)">无回复数据</div>';
  let html = '<div class="response-block">';
  if (resp.reasoning) {
    html += `<div class="reasoning-box"><div class="reas-label">💭 推理过程</div><div class="reas-text">${esc(sanitizeDisplayValue(resp.reasoning, "reasoning"))}</div></div>`;
  }
  if (resp.content) {
    html += `<div class="content-box">${esc(sanitizeDisplayValue(resp.content, "content"))}</div>`;
  }
  if (resp.toolCalls && resp.toolCalls.length) {
    html += '<div class="resp-tool-calls"><h5>模型工具调用</h5><div class="tool-grid">';
    for (const tc of resp.toolCalls) {
      if (!tc) continue;
      const fn = tc.function || {};
      let args = fn.arguments || "";
      let argsHtml;
      try { argsHtml = '<div class="json-view">' + highlightJSON(JSON.parse(args)) + '</div>'; }
      catch { argsHtml = `<pre>${esc(sanitizeDisplayValue(args, "arguments"))}</pre>`; }
      html += `<div class="tool-card"><div class="tool-card-head" onclick="this.parentElement.classList.toggle('closed')"><span class="tool-icon">⚙</span><span class="tool-fname">${esc(fn.name || "")}</span></div><div class="tool-card-body">${argsHtml}</div></div>`;
    }
    html += '</div></div>';
  }
  if (resp.finish) html += `<div class="finish-info">finish_reason: ${esc(resp.finish)}</div>`;
  html += '</div>';
  return html;
}

/* ── Event listeners ──────────────────────────────── */

document.getElementById("traceList").addEventListener("click", async (e) => {
  const card = e.target.closest(".trace-card");
  if (!card) return;
  document.querySelectorAll(".trace-card.active").forEach(c => c.classList.remove("active"));
  card.classList.add("active");
  state.selectedTraceId = card.dataset.id;
  await loadDetail(card.dataset.id);
});

document.getElementById("searchForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  state.page = 1;
  state.filters = {};
  for (const [k, v] of fd.entries()) { if (v) state.filters[k] = v; }
  const tfrom = document.getElementById("filterTimeFrom").value;
  const tto = document.getElementById("filterTimeTo").value;
  if (tfrom) state.filters.time_from = new Date(tfrom).getTime() / 1000;
  if (tto) state.filters.time_to = new Date(tto).getTime() / 1000;
  const dmin = document.getElementById("filterDurMin").value;
  const dmax = document.getElementById("filterDurMax").value;
  if (dmin) state.filters.duration_min = parseFloat(dmin);
  if (dmax) state.filters.duration_max = parseFloat(dmax);
  loadLogs();
});

document.getElementById("toggleFilters").addEventListener("click", () => {
  const el = document.getElementById("advancedFilters");
  el.style.display = el.style.display === "none" ? "" : "none";
});

document.querySelectorAll(".qtime-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".qtime-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    const hours = parseInt(btn.dataset.hours);
    const fromEl = document.getElementById("filterTimeFrom");
    const toEl = document.getElementById("filterTimeTo");
    if (hours === 0) { fromEl.value = ""; toEl.value = ""; }
    else {
      const now = new Date();
      fromEl.value = toLocalISO(new Date(now.getTime() - hours * 3600000));
      toEl.value = toLocalISO(now);
    }
    document.getElementById("searchForm").dispatchEvent(new Event("submit", { cancelable: true }));
  });
});

document.querySelectorAll(".qdur-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".qdur-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("filterDurMin").value = btn.dataset.min;
    document.getElementById("filterDurMax").value = btn.dataset.max;
    document.getElementById("searchForm").dispatchEvent(new Event("submit", { cancelable: true }));
  });
});

document.getElementById("clearFilters").addEventListener("click", clearAllFilters);
document.getElementById("clearFiltersQuick").addEventListener("click", clearAllFilters);

function clearAllFilters() {
  document.getElementById("searchForm").reset();
  document.getElementById("filterTimeFrom").value = "";
  document.getElementById("filterTimeTo").value = "";
  document.getElementById("filterDurMin").value = "";
  document.getElementById("filterDurMax").value = "";
  document.querySelectorAll(".qtime-btn.active, .qdur-btn.active").forEach(b => b.classList.remove("active"));
  state.filters = {};
  state.page = 1;
  loadLogs();
}

document.getElementById("refreshLogs").addEventListener("click", () => loadLogs());

// Category bar
document.querySelectorAll("#categoryBar .cat-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#categoryBar .cat-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    state.pathFilter = btn.dataset.path;
    state.page = 1;
    loadLogs();
  });
});

document.getElementById("prevPage").addEventListener("click", () => {
  if (state.page > 1) { state.page--; loadLogs(); }
});
document.getElementById("nextPage").addEventListener("click", () => {
  if (state.page < state.pages) { state.page++; loadLogs(); }
});
document.getElementById("pageSize").addEventListener("change", (e) => {
  state.pageSize = parseInt(e.target.value, 10);
  state.page = 1;
  loadLogs();
});

/* ── Init ─────────────────────────────────────────── */

fetch("/healthz").then(r => r.json()).then(d => {
  if (d.version) document.getElementById("versionInfo").textContent = "v" + d.version;
}).catch(() => {});

loadKeysFromStorage();
renderKeyList();
if (getActiveKeyHashes().length > 0) {
  verifyKeys();
  loadLogs();
}
