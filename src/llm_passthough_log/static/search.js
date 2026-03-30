/* ═══════════════════════════════════════════════════
   LLM Log Search — Public Search Page JS
   ═══════════════════════════════════════════════════ */

const state = {
  page: 1,
  pages: 1,
  filters: {},
  pathFilter: "chat/completions",
  selectedTraceId: null,
  detailEntry: null,
  // Key management - stored in localStorage
  keys: [], // [{id, key, label, active, maskedKey}]
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

function loadKeysFromStorage() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) state.keys = JSON.parse(raw);
  } catch { state.keys = []; }
}

function saveKeysToStorage() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.keys));
}

function getActiveKeys() {
  return state.keys.filter(k => k.active).map(k => k.key);
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
      const displayName = k.label ? esc(k.label) : esc(k.maskedKey || maskKeyDisplay(k.key));
      const subtitle = k.label ? esc(k.maskedKey || maskKeyDisplay(k.key)) : '';
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
        <button class="key-edit-btn" data-edit="${k.id}" title="编辑别名" onclick="event.stopPropagation()">✎</button>
        <button class="key-del-btn" data-del="${k.id}" title="删除" onclick="event.stopPropagation()">✕</button>
      </div>`;
    }).join("");
  }
  document.getElementById("activeKeyCount").textContent = getActiveKeys().length;
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
  const hasActiveKeys = getActiveKeys().length > 0;
  document.getElementById("noKeyOverlay").style.display = hasActiveKeys ? "none" : "";
  document.getElementById("mainArea").style.display = hasActiveKeys ? "" : "none";
}

async function verifyKeys() {
  const activeKeys = getActiveKeys();
  if (!activeKeys.length) return;
  try {
    const resp = await fetch("/search/api/verify-keys", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ keys: activeKeys }),
    });
    if (!resp.ok) return;
    const data = await resp.json();
    // Update counts
    if (data.keys) {
      for (const k of state.keys) {
        // Find hash matching this key
        for (const [hash, info] of Object.entries(data.keys)) {
          if (info.masked_key === maskSecretText(k.key) || k.maskedKey === info.masked_key) {
            k.count = info.count;
          }
        }
      }
      // Simpler approach: verify by index
      const keyToHash = {};
      for (const [hash, info] of Object.entries(data.keys)) {
        // We can match by the masked key pattern
        for (const k of state.keys) {
          if (k.active) {
            // SHA-256 hash of key
            const testHash = await sha256(k.key);
            if (testHash === hash) {
              k.count = info.count;
              k.maskedKey = info.masked_key;
            }
          }
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
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Add key
document.getElementById("addKeyBtn").addEventListener("click", () => {
  const keyInput = document.getElementById("newKeyInput");
  const labelInput = document.getElementById("newKeyLabel");
  const key = keyInput.value.trim();
  if (!key) { keyInput.focus(); return; }
  // Check duplicate
  if (state.keys.some(k => k.key === key)) {
    alert("该 Key 已存在"); return;
  }
  state.keys.push({
    id: generateId(),
    key: key,
    label: labelInput.value.trim(),
    active: true,
    maskedKey: maskKeyDisplay(key),
    count: null,
  });
  keyInput.value = "";
  labelInput.value = "";
  saveKeysToStorage();
  renderKeyList();
  verifyKeys().then(() => {
    if (getActiveKeys().length > 0) loadLogs();
  });
});

document.getElementById("newKeyInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); document.getElementById("addKeyBtn").click(); }
});

// Toggle / Delete / Edit keys
document.getElementById("keyList").addEventListener("click", (e) => {
  // Checkbox toggle
  const toggleCb = e.target.closest("[data-toggle]");
  if (toggleCb) {
    const kid = toggleCb.dataset.toggle;
    const k = state.keys.find(x => x.id === kid);
    if (k) { k.active = toggleCb.checked; saveKeysToStorage(); renderKeyList(); if (getActiveKeys().length > 0) loadLogs(); }
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
    state.keys = state.keys.filter(x => x.id !== kid);
    saveKeysToStorage();
    renderKeyList();
    if (getActiveKeys().length > 0) loadLogs();
    return;
  }
  // Click on card body to toggle
  const card = e.target.closest(".key-item");
  if (card && !e.target.closest("input, button, .key-edit-inline")) {
    const kid = card.dataset.kid;
    const k = state.keys.find(x => x.id === kid);
    if (k) { k.active = !k.active; saveKeysToStorage(); renderKeyList(); if (getActiveKeys().length > 0) loadLogs(); }
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
  if (getActiveKeys().length > 0) loadLogs();
});

document.getElementById("deselectAllKeys").addEventListener("click", () => {
  state.keys.forEach(k => k.active = false);
  saveKeysToStorage(); renderKeyList();
});

// Collapse/expand key panel
document.getElementById("toggleKeyPanel").addEventListener("click", () => {
  const body = document.getElementById("keyPanelBody");
  const btn = document.getElementById("toggleKeyPanel");
  const collapsed = body.style.display === "none";
  body.style.display = collapsed ? "" : "none";
  btn.textContent = collapsed ? "▾" : "▸";
  btn.closest(".key-manager").classList.toggle("collapsed", !collapsed);
});

/* ── API calls ────────────────────────────────────── */

async function fetchSearchAPI(url, body) {
  body.keys = getActiveKeys();
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
  const activeKeys = getActiveKeys();
  if (!activeKeys.length) return;

  const body = {
    ...state.filters,
    path_contains: state.pathFilter,
    page: state.page,
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
  state.filters.q = fp;
  state.page = 1;
  const searchInput = document.querySelector('#searchForm input[name="q"]');
  if (searchInput) searchInput.value = fp;
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
  return { reasoning, content, model, finish, usage, toolCalls: toolCalls.length ? toolCalls : null };
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
        <button class="tab-btn active" data-tab="messages">消息 <span class="tab-badge">${msgCount}</span></button>
        ${toolCount ? `<button class="tab-btn" data-tab="tools">工具 <span class="tab-badge">${toolCount}</span></button>` : ""}
        <button class="tab-btn" data-tab="response">回复${respToolCount ? ` <span class="tab-badge">${respToolCount} calls</span>` : ""}</button>
        ${entry.conv_fingerprint ? '<button class="tab-btn" data-tab="timeline">会话时间线</button>' : ""}
        <button class="tab-btn" data-tab="raw">JSON</button>
      </div>
    </div>
    <div class="detail-body">
  `;

  // ── Tab: Messages ──
  html += '<div class="tab-panel active" data-panel="messages">';
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

document.getElementById("clearFilters").addEventListener("click", () => {
  document.getElementById("searchForm").reset();
  document.getElementById("filterTimeFrom").value = "";
  document.getElementById("filterTimeTo").value = "";
  document.getElementById("filterDurMin").value = "";
  document.getElementById("filterDurMax").value = "";
  document.querySelectorAll(".qtime-btn.active").forEach(b => b.classList.remove("active"));
  state.filters = {};
  state.page = 1;
  loadLogs();
});

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

/* ── Init ─────────────────────────────────────────── */

loadKeysFromStorage();
renderKeyList();
if (getActiveKeys().length > 0) {
  verifyKeys();
  loadLogs();
}
