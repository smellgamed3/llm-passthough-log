/* ═══════════════════════════════════════════════════
   LLM Proxy Console — Full Redesign JS
   ═══════════════════════════════════════════════════ */

const state = {
  page: 1,
  pages: 1,
  filters: {},
  activeTab: "friendly",
  detailEntry: null,
  selectedTraceId: null,
  userPage: 1,
  userPages: 1,
  userQuery: "",
  pathFilter: "chat/completions",
  sessionToken: localStorage.getItem("llm_proxy_session_token") || "",
  currentUser: null,
  allProviders: [],
};

/* ── Utility ──────────────────────────────────────── */

function esc(v) {
  return String(v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

async function fetchJSON(url, opts) {
  opts = opts || {};
  if (!opts.headers) opts.headers = {};
  if (state.sessionToken) opts.headers["X-Session-Token"] = state.sessionToken;
  const r = await fetch(url, opts);
  if (r.status === 401) { showLogin(); throw new Error("需要登录"); }
  const t = await r.text();
  let d; try { d = JSON.parse(t); } catch { throw new Error("非 JSON: " + t.slice(0, 200)); }
  if (!r.ok) throw new Error(d.detail || "请求失败: " + r.status);
  return d;
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

function buildQuery(p) {
  const q = new URLSearchParams();
  Object.entries(p).forEach(([k, v]) => { if (v !== "" && v != null) q.set(k, String(v)); });
  return q.toString();
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => {
    // brief feedback
  });
}

function fmtCost(v) {
  if (!v || v <= 0) return "";
  if (v < 0.001) return "$" + v.toFixed(6);
  if (v < 0.01) return "$" + v.toFixed(4);
  return "$" + v.toFixed(3);
}

function estimateTokenCount(text) {
  if (!text) return 0;
  const normalized = String(text);
  const asciiChars = (normalized.match(/[\u0000-\u007f]/g) || []).length;
  const nonAsciiChars = normalized.length - asciiChars;
  return Math.max(1, Math.round(asciiChars / 4 + nonAsciiChars * 1.15));
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
  const promptParts = [];
  if (requestBody && typeof requestBody === "object") {
    if (typeof requestBody.prompt === "string") promptParts.push(requestBody.prompt);
    if (typeof requestBody.input === "string") promptParts.push(requestBody.input);
    if (Array.isArray(requestBody.messages)) {
      requestBody.messages.forEach(msg => promptParts.push(collectContentText(msg?.content)));
    }
  }
  const responseParts = [];
  if (resp?.content) responseParts.push(resp.content);
  if (resp?.reasoning) responseParts.push(resp.reasoning);
  if (Array.isArray(resp?.toolCalls)) {
    resp.toolCalls.forEach(tc => responseParts.push(tc?.function?.arguments || ""));
  }
  const promptText = promptParts.filter(Boolean).join("\n");
  const completionText = responseParts.filter(Boolean).join("\n");
  if (!promptText && !completionText) return null;
  const promptTokens = estimateTokenCount(promptText);
  const completionTokens = estimateTokenCount(completionText);
  return {
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: promptTokens + completionTokens,
    estimated: true,
    prompt_chars: promptText.length,
    completion_chars: completionText.length,
  };
}

/* ── 登录 / 角色 ─────────────────────────────────── */

function showLogin() {
  const dlg = document.getElementById("loginDialog");
  document.getElementById("loginError").style.display = "none";
  document.getElementById("loginName").value = "";
  document.getElementById("loginPassword").value = "";
  dlg.showModal();
}

function applyRole(role) {
  document.body.classList.toggle("role-admin", role === "admin");
  const loginUser = document.getElementById("loginUser");
  const logoutBtn = document.getElementById("logoutBtn");
  if (state.currentUser) {
    loginUser.textContent = state.currentUser.name + (role === "admin" ? " (管理员)" : "");
    logoutBtn.style.display = "";
  }
  // Hide user/provider nav for non-admin
  document.querySelectorAll(".nav-btn").forEach(btn => {
    if (btn.classList.contains("admin-only") && role !== "admin") {
      btn.style.display = "none";
    } else {
      btn.style.display = "";
    }
  });
}

document.getElementById("loginSubmitBtn").addEventListener("click", async () => {
  const name = document.getElementById("loginName").value.trim();
  const password = document.getElementById("loginPassword").value;
  if (!name || !password) return;
  try {
    const r = await fetch("/admin/api/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name, password }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "登录失败");
    state.sessionToken = data.session_token || "";
    state.currentUser = data.user;
    if (state.sessionToken) localStorage.setItem("llm_proxy_session_token", state.sessionToken);
    document.getElementById("loginDialog").close();
    applyRole(data.user.role);
    boot();
  } catch (err) {
    const el = document.getElementById("loginError");
    el.textContent = err.message;
    el.style.display = "";
  }
});

document.getElementById("loginPassword").addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("loginSubmitBtn").click();
});

document.getElementById("logoutBtn").addEventListener("click", () => {
  fetchJSON("/admin/api/logout", { method: "POST" }).catch(() => {});
  state.sessionToken = "";
  state.currentUser = null;
  localStorage.removeItem("llm_proxy_session_token");
  location.reload();
});

/* ── JSON 语法高亮 ────────────────────────────────── */

function highlightJSON(obj, indent) {
  indent = indent || 0;
  const pad = "  ".repeat(indent);
  if (obj === null) return '<span class="jnull">null</span>';
  if (typeof obj === "boolean") return `<span class="jb">${obj}</span>`;
  if (typeof obj === "number") return `<span class="jn">${obj}</span>`;
  if (typeof obj === "string") {
    const s = JSON.stringify(obj);
    if (s.length > 500) {
      return `<span class="js">${esc(s.slice(0, 400))}</span><span class="jnull">…(${s.length} chars)</span><span class="js">${esc(s.slice(-50))}</span>`;
    }
    return `<span class="js">${esc(s)}</span>`;
  }
  if (Array.isArray(obj)) {
    if (!obj.length) return '<span class="jpunc">[]</span>';
    const items = obj.map(v => pad + "  " + highlightJSON(v, indent + 1));
    return '<span class="jpunc">[</span>\n' + items.join(',\n') + '\n' + pad + '<span class="jpunc">]</span>';
  }
  if (typeof obj === "object") {
    const keys = Object.keys(obj);
    if (!keys.length) return '<span class="jpunc">{}</span>';
    const entries = keys.map(k => {
      return pad + '  <span class="jk">' + esc(JSON.stringify(k)) + '</span><span class="jpunc">: </span>' + highlightJSON(obj[k], indent + 1);
    });
    return '<span class="jpunc">{</span>\n' + entries.join(',\n') + '\n' + pad + '<span class="jpunc">}</span>';
  }
  return esc(String(obj));
}

/* ── SSE 解析 ─────────────────────────────────────── */

function parseSSE(raw) {
  if (typeof raw !== "string") return null;
  const lines = raw.split("\n");
  let reasoning = "", content = "", model = "", finish = "";
  let usage = null, toolCalls = [];
  for (const ln of lines) {
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
            if (tc.type) toolCalls[idx].type = tc.type;
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
    return {
      reasoning: m.reasoning_content || "",
      content: m.content || "",
      model: rb.model || "",
      finish: ch?.finish_reason || "",
      usage: rb.usage || null,
      toolCalls: m.tool_calls || null,
    };
  }
  if (typeof rb === "string") return parseSSE(rb);
  return null;
}

/* ── 导航 ─────────────────────────────────────────── */

document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
    document.getElementById("view" + capitalize(btn.dataset.view)).classList.add("active");
  });
});

function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

/* ── 概览 ─────────────────────────────────────────── */

async function loadOverview() {
  const p = await fetchJSON("/admin/api/overview");
  const t = p.data.totals || {};
  if (p.downstream_url) {
    document.getElementById("downstreamUrl").textContent = p.downstream_url || "-";
    document.getElementById("downstreamUrl").title = p.downstream_url || "";
  }
  document.getElementById("queueSize").textContent = p.queue_size ?? 0;

  const cards = [
    statCard("总请求数", t.total_requests ?? 0),
    statCard("流式", t.stream_requests ?? 0),
    statCard("错误", t.error_requests ?? 0),
    statCard("Models", t.models ?? 0),
    statCard("最后请求", fmtTimeFull(t.latest_request_at)),
  ];
  if (t.total_cost > 0) cards.push(statCard("总成本", fmtCost(t.total_cost)));
  document.getElementById("statsCards").innerHTML = cards.join("");

  renderChips("statusList", p.data.statuses || [], i => `<strong>${esc(i.status)}</strong><span>${i.count}</span>`);
}

function statCard(l, v) {
  return `<div class="stat-card"><span>${l}</span><strong>${esc(String(v))}</strong></div>`;
}

function renderChips(id, items, fn) {
  const el = document.getElementById(id);
  el.innerHTML = items.length ? items.map(i => `<div class="chip">${fn(i)}</div>`).join("") : '<span style="color:var(--text-muted)">暂无</span>';
}

document.getElementById("refreshOverview").addEventListener("click", loadOverview);

/* ── Trace 列表 ───────────────────────────────────── */

async function loadLogs() {
  const q = buildQuery({ ...state.filters, path_contains: state.pathFilter, page: state.page });
  const p = await fetchJSON(`/admin/api/logs?${q}`);
  const { items, pagination } = p;
  state.pages = pagination.pages;

  document.getElementById("pageInfo").textContent = `${pagination.page} / ${pagination.pages}`;
  document.getElementById("logMeta").textContent = `${pagination.total} 条记录`;
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
    return `
      <div class="trace-card${active}" data-id="${i.id}">
        <div class="tc-row1">
          <span class="tc-method ${methodCls}">${esc(i.method)}</span>
          <span class="tc-model">${esc(i.request_model || i.path)}</span>
          ${stream}
          ${cost}
          <span class="tc-status ${statusCls}">${i.response_status ?? "-"}</span>
        </div>
        <div class="tc-row2">
          <span class="tc-time">${fmtTime(i.created_at)}</span>
          <span class="tc-dur">${fmtMs(i.duration_ms)}</span>
          <span class="tc-preview">${esc(i.preview || "")}</span>
        </div>
      </div>`;
  }).join("");
}

document.getElementById("traceList").addEventListener("click", async (e) => {
  const card = e.target.closest(".trace-card");
  if (!card) return;
  document.querySelectorAll(".trace-card.active").forEach(c => c.classList.remove("active"));
  card.classList.add("active");
  state.selectedTraceId = card.dataset.id;
  await loadDetail(card.dataset.id);
});

document.getElementById("searchForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  state.page = 1;
  state.filters = {};
  for (const [k, v] of fd.entries()) { if (v) state.filters[k] = v; }
  // Collect time/duration filters from standalone inputs
  const tfrom = document.getElementById("filterTimeFrom").value;
  const tto = document.getElementById("filterTimeTo").value;
  if (tfrom) state.filters.time_from = new Date(tfrom).getTime() / 1000;
  if (tto) state.filters.time_to = new Date(tto).getTime() / 1000;
  const dmin = document.getElementById("filterDurMin").value;
  const dmax = document.getElementById("filterDurMax").value;
  if (dmin) state.filters.duration_min = parseFloat(dmin);
  if (dmax) state.filters.duration_max = parseFloat(dmax);
  await loadLogs();
});

document.getElementById("toggleFilters").addEventListener("click", () => {
  const el = document.getElementById("advancedFilters");
  el.style.display = el.style.display === "none" ? "" : "none";
});

/* -- Quick time range buttons -- */
document.querySelectorAll(".qtime-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".qtime-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    const hours = parseInt(btn.dataset.hours);
    const fromEl = document.getElementById("filterTimeFrom");
    const toEl = document.getElementById("filterTimeTo");
    if (hours === 0) {
      fromEl.value = "";
      toEl.value = "";
    } else {
      const now = new Date();
      const from = new Date(now.getTime() - hours * 3600000);
      fromEl.value = toLocalISO(from);
      toEl.value = toLocalISO(now);
    }
    document.getElementById("searchForm").dispatchEvent(new Event("submit", { cancelable: true }));
  });
});

/* -- Quick duration range buttons -- */
document.querySelectorAll(".qdur-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".qdur-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("filterDurMin").value = btn.dataset.min;
    document.getElementById("filterDurMax").value = btn.dataset.max;
    document.getElementById("searchForm").dispatchEvent(new Event("submit", { cancelable: true }));
  });
});

/* -- Clear all filters -- */
document.getElementById("clearFilters").addEventListener("click", () => {
  document.getElementById("searchForm").reset();
  document.getElementById("filterTimeFrom").value = "";
  document.getElementById("filterTimeTo").value = "";
  document.getElementById("filterDurMin").value = "";
  document.getElementById("filterDurMax").value = "";
  document.querySelectorAll(".qtime-btn.active, .qdur-btn.active").forEach(b => b.classList.remove("active"));
  state.filters = {};
  state.page = 1;
  loadLogs();
});

function toLocalISO(d) {
  const off = d.getTimezoneOffset();
  const local = new Date(d.getTime() - off * 60000);
  return local.toISOString().slice(0, 16);
}

document.getElementById("refreshLogs").addEventListener("click", () => loadLogs());

/* ── Category 筛选 ─────────────────────────────────── */

function initCategoryBar() {
  const bar = document.getElementById("categoryBar");
  bar.querySelectorAll(".cat-btn").forEach(btn => {
    if (btn.dataset.path === state.pathFilter) btn.classList.add("active");
    btn.addEventListener("click", () => {
      bar.querySelectorAll(".cat-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.pathFilter = btn.dataset.path;
      state.page = 1;
      loadLogs();
    });
  });
}
initCategoryBar();

document.getElementById("prevPage").addEventListener("click", () => {
  if (state.page > 1) { state.page--; loadLogs(); }
});
document.getElementById("nextPage").addEventListener("click", () => {
  if (state.page < state.pages) { state.page++; loadLogs(); }
});

/* ── Trace 详情渲染 ───────────────────────────────── */

async function loadDetail(id) {
  const entry = await fetchJSON(`/admin/api/logs/${id}`);
  state.detailEntry = entry;
  state.activeTab = "friendly";
  renderDetail(entry);
}

function renderDetail(entry) {
  const pane = document.getElementById("detailPane");
  const resp = extractResponse(entry);
  const reqBody = entry.request_body;
  const messages = (reqBody && typeof reqBody === "object") ? reqBody.messages : null;
  const tools = (reqBody && typeof reqBody === "object") ? (reqBody.tools || reqBody.functions) : null;
  const usage = resp?.usage || null;
  const statusCls = (entry.response_status >= 400) ? "err" : "ok";
  const model = reqBody?.model || resp?.model || "-";

  // Build tab badges
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
        <div class="dm-item"><span class="dm-label">客户端</span><span class="dm-value">${esc(entry.client || "-")}</span></div>
        ${entry.user_name ? `<div class="dm-item"><span class="dm-label">用户</span><span class="dm-value">${esc(entry.user_name)}</span></div>` : ""}
        <div class="dm-item"><span class="dm-label">响应大小</span><span class="dm-value">${fmtBytes(entry.response_size)}</span></div>
        <div class="dm-item"><span class="dm-label">时间</span><span class="dm-value">${fmtTimeFull(entry.timestamp)}</span></div>
        ${usage ? `<div class="dm-item"><span class="dm-label">Tokens</span><span class="dm-value">${usage.total_tokens ?? (usage.prompt_tokens || 0) + (usage.completion_tokens || 0)}</span></div>` : ""}
        ${entry.estimated_cost ? `<div class="dm-item"><span class="dm-label">成本</span><span class="dm-value cost-value">${fmtCost(entry.estimated_cost)}</span></div>` : ""}
      </div>
      <div class="detail-tabs">
        <button class="tab-btn active" data-tab="friendly">友好视图</button>
        <button class="tab-btn" data-tab="messages">消息 <span class="tab-badge">${msgCount}</span></button>
        ${toolCount ? `<button class="tab-btn" data-tab="tools">工具 <span class="tab-badge">${toolCount}</span></button>` : ""}
        <button class="tab-btn" data-tab="response">回复${respToolCount ? ` <span class="tab-badge">${respToolCount} calls</span>` : ""}</button>
        <button class="tab-btn" data-tab="headers">Headers</button>
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
    html += renderMsgThread(messages, true);
    html += '</div>';
  }
  html += renderResponseBlock(resp);
  html += '</div>';

  // ── Tab: Messages ──
  html += '<div class="tab-panel" data-panel="messages">';
  if (messages && messages.length) {
    html += renderMsgThread(messages, false);
  } else {
    html += '<div style="color:var(--text-muted)">无消息数据</div>';
  }
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
  if (entry.response_body && typeof entry.response_body === "object") {
    html += '<div style="margin-top:16px">';
    html += '<div class="collapse-section"><div class="collapse-head" onclick="this.parentElement.classList.toggle(\'closed\')"><span class="collapse-arrow">▼</span>原始 response_body</div>';
    html += '<div class="collapse-body"><div class="json-view">' + highlightJSON(entry.response_body) + '</div></div></div>';
    html += '</div>';
  }
  html += '</div>';

  // ── Tab: Headers ──
  html += '<div class="tab-panel" data-panel="headers">';
  html += renderHeadersSection("请求头", entry.request_headers);
  html += renderHeadersSection("响应头", entry.response_headers);
  html += '</div>';

  // ── Tab: Raw ──
  html += '<div class="tab-panel" data-panel="raw">';
  html += '<div class="json-view">' + highlightJSON(entry) + '</div>';
  html += '</div>';

  html += '</div>'; // close detail-body

  pane.innerHTML = html;
  pane.className = "";

  // Tab navigation
  pane.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      pane.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      pane.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      pane.querySelector(`[data-panel="${btn.dataset.tab}"]`).classList.add("active");
    });
  });
}

/* ── Token 面板 ───────────────────────────────────── */

function renderTokenPanel(usage, entry, resp) {
  const effectiveUsage = usage || estimateUsage(entry, resp);
  if (!effectiveUsage) return "";
  const prompt = effectiveUsage.prompt_tokens ?? 0;
  const compl = effectiveUsage.completion_tokens ?? 0;
  const total = effectiveUsage.total_tokens || (prompt + compl);
  const reasoning = effectiveUsage.completion_tokens_details?.reasoning_tokens ?? 0;
  const cached = effectiveUsage.prompt_tokens_details?.cached_tokens ?? 0;
  const actualPrompt = prompt - cached;
  const actualCompl = compl - reasoning;

  const segs = [];
  if (total > 0) {
    if (cached > 0) segs.push({ c: "cached", p: cached/total*100, l: `缓存 ${cached}` });
    if (actualPrompt > 0) segs.push({ c: "prompt", p: actualPrompt/total*100, l: `Prompt ${actualPrompt}` });
    if (reasoning > 0) segs.push({ c: "reasoning", p: reasoning/total*100, l: `推理 ${reasoning}` });
    if (actualCompl > 0) segs.push({ c: "completion", p: actualCompl/total*100, l: `输出 ${actualCompl}` });
  }

  const bar = segs.map(s =>
    `<div class="tbar-seg ${s.c}" style="width:${Math.max(s.p,2).toFixed(1)}%" title="${s.l}">${s.p > 12 ? s.l : ""}</div>`
  ).join("");

  const items = [];
  items.push(tsItem("prompt", "Prompt", prompt));
  if (cached > 0) items.push(tsItem("cached", "缓存命中", cached));
  items.push(tsItem("completion", "Completion", compl));
  if (reasoning > 0) items.push(tsItem("reasoning", "推理", reasoning));
  items.push(`<div class="ts-item"><strong style="font-size:14px">总计 ${total}</strong></div>`);
  if (cached > 0 && prompt > 0) {
    items.push(`<div class="ts-item">缓存率<strong>${((cached/prompt)*100).toFixed(1)}%</strong></div>`);
  }
  if (effectiveUsage.estimated) {
    items.push(`<div class="ts-item">Prompt 字符<strong>${effectiveUsage.prompt_chars}</strong></div>`);
    items.push(`<div class="ts-item">输出字符<strong>${effectiveUsage.completion_chars}</strong></div>`);
  }
  const note = effectiveUsage.estimated
    ? '<div class="token-note">当前记录未返回官方 usage，以上为字符长度估算；新流式请求已自动补齐 usage 回传。</div>'
    : "";
  const title = effectiveUsage.estimated ? "Token 用量（估算）" : "Token 用量";
  return `<div class="token-panel"><h4>${title}</h4><div class="token-bar">${bar}</div><div class="token-stats">${items.join("")}</div>${note}</div>`;
}

function tsItem(cls, label, val) {
  return `<div class="ts-item"><span class="ts-dot ${cls}"></span>${label}<strong>${val}</strong></div>`;
}

/* ── 请求参数 ─────────────────────────────────────── */

function renderParamsSection(body) {
  if (!body || typeof body !== "object") return "";
  const skip = new Set(["messages","tools","functions","tool_choice","function_call"]);
  const params = Object.entries(body).filter(([k]) => !skip.has(k));
  if (!params.length) return "";

  return '<div class="params-section">' + params.map(([k, v]) => {
    let display = v;
    if (typeof v === "object" && v !== null) display = JSON.stringify(v);
    return `<div class="param-chip"><div class="pk">${esc(k)}</div><div class="pv">${esc(String(display))}</div></div>`;
  }).join("") + '</div>';
}

/* ── 消息线程 ─────────────────────────────────────── */

function renderMsgThread(messages, compact) {
  let html = '<div class="msg-thread">';
  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    const role = m.role || "unknown";
    // In compact mode: collapse history messages (not first system, not last user)
    const isSystem = role === "system";
    const isLast = i === messages.length - 1;
    const autoOpen = compact ? (isSystem || isLast) : true;
    html += renderMsgBubble(m, i, messages.length, autoOpen);
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
    bodyHtml = `<div class="msg-content">${esc(content)}</div>`;
  } else if (Array.isArray(content)) {
    meta = `${content.length} 部分`;
    const parts = content.map(p => {
      if (p.type === "text") return `<div style="white-space:pre-wrap">${esc(p.text || "")}</div>`;
      if (p.type === "image_url") return `<div style="color:var(--text-muted)">[图片: ${esc((p.image_url?.url || "").slice(0, 80))}…]</div>`;
      return `<div><pre style="margin:0">${esc(JSON.stringify(p, null, 2))}</pre></div>`;
    }).join("");
    bodyHtml = `<div class="msg-content msg-content-multipart">${parts}</div>`;
  } else if (content == null) {
    if (msg.tool_calls) {
      meta = `${msg.tool_calls.length} 个工具调用`;
      bodyHtml = '<div class="msg-content">' + msg.tool_calls.map(tc => {
        const fn = tc.function || {};
        let args = fn.arguments || "";
        try { args = JSON.stringify(JSON.parse(args), null, 2); } catch {}
        return `<div class="tool-card" style="margin-bottom:6px"><div class="tool-card-head" onclick="event.stopPropagation();this.parentElement.classList.toggle('closed')"><span class="tool-icon">⚙</span><span class="tool-fname">${esc(fn.name || "")}</span><span class="tool-arrow">▼</span></div><div class="tool-card-body"><pre>${esc(args)}</pre></div></div>`;
      }).join("") + '</div>';
    } else if (msg.function_call) {
      meta = "函数调用";
      bodyHtml = `<div class="msg-content"><pre style="margin:0">${esc(JSON.stringify(msg.function_call, null, 2))}</pre></div>`;
    } else {
      bodyHtml = '<div class="msg-content" style="color:var(--text-muted)">（空）</div>';
    }
  } else {
    bodyHtml = `<div class="msg-content"><pre style="margin:0">${esc(JSON.stringify(content, null, 2))}</pre></div>`;
  }

  let extraInfo = "";
  if (msg.tool_call_id) extraInfo += `<span style="font-family:var(--mono);font-size:10px">id: ${esc(msg.tool_call_id.slice(0,12))}…</span>`;
  if (msg.name) extraInfo += `<span>${esc(msg.name)}</span>`;

  const copyData = typeof content === "string" ? content : JSON.stringify(content ?? msg.tool_calls ?? msg.function_call, null, 2);

  return `
    <div class="msg-bubble${collapsed}">
      <div class="msg-bubble-head" onclick="this.parentElement.classList.toggle('collapsed')">
        <span class="msg-role-tag ${role}">${role}</span>
        <span class="msg-info">#${idx + 1} ${meta ? "· " + meta : ""} ${extraInfo}</span>
        <button class="copy-btn" onclick="event.stopPropagation();copyText(${esc(JSON.stringify(copyData))})">复制</button>
        <span class="msg-arrow">▼</span>
      </div>
      ${bodyHtml}
    </div>`;
}

/* ── 工具定义 ─────────────────────────────────────── */

function renderToolsDef(tools) {
  if (!tools || !tools.length) return "";
  return '<div class="tool-grid">' + tools.map(t => {
    const fn = t.function || t;
    const name = fn.name || "(unnamed)";
    const desc = fn.description || "";
    const params = fn.parameters;

    let bodyHtml = "";
    if (params) {
      // Try to render as parameter table
      if (params.properties && typeof params.properties === "object") {
        const required = new Set(params.required || []);
        const rows = Object.entries(params.properties).map(([pname, pdef]) => {
          const ptype = pdef.type || "";
          const pdesc = pdef.description || "";
          const penum = pdef.enum ? pdef.enum.join(", ") : "";
          const reqBadge = required.has(pname) ? '<span class="preq">必需</span>' : "";
          return `<tr><td class="pname">${esc(pname)} ${reqBadge}</td><td class="ptype">${esc(ptype)}</td><td class="pdesc">${esc(pdesc)}${penum ? ` (${esc(penum)})` : ""}</td></tr>`;
        }).join("");
        bodyHtml = `<table class="tool-param-table"><thead><tr><th>参数</th><th>类型</th><th>说明</th></tr></thead><tbody>${rows}</tbody></table>`;
      } else {
        bodyHtml = `<pre>${esc(JSON.stringify(params, null, 2))}</pre>`;
      }
    }

    return `
      <div class="tool-card closed" onclick="this.classList.toggle('closed')">
        <div class="tool-card-head">
          <span class="tool-icon">⚙</span>
          <span class="tool-fname">${esc(name)}</span>
          <span class="tool-desc-text">${esc(desc.slice(0, 100))}</span>
          <span class="tool-arrow">▼</span>
        </div>
        ${bodyHtml ? `<div class="tool-card-body">${bodyHtml}</div>` : ""}
      </div>`;
  }).join("") + '</div>';
}

/* ── 回复区块 ─────────────────────────────────────── */

function renderResponseBlock(resp) {
  if (!resp) return '<div style="color:var(--text-muted)">无回复数据</div>';
  let html = '<div class="response-block">';

  if (resp.reasoning) {
    html += `<div class="reasoning-box"><div class="reas-label">💭 推理过程 <span style="font-weight:400;color:var(--text-muted)">(${resp.reasoning.length} 字符)</span></div><div class="reas-text">${esc(resp.reasoning)}</div></div>`;
  }

  if (resp.content) {
    html += `<div class="content-box">${esc(resp.content)}</div>`;
  }

  if (resp.toolCalls && resp.toolCalls.length) {
    html += '<div class="resp-tool-calls"><h5>模型工具调用</h5><div class="tool-grid">';
    for (const tc of resp.toolCalls) {
      const fn = tc.function || {};
      let args = fn.arguments || "";
      let argsHtml;
      try {
        const parsed = JSON.parse(args);
        argsHtml = '<div class="json-view" style="max-height:300px">' + highlightJSON(parsed) + '</div>';
      } catch {
        argsHtml = `<pre>${esc(args)}</pre>`;
      }
      html += `<div class="tool-card"><div class="tool-card-head" onclick="this.parentElement.classList.toggle('closed')"><span class="tool-icon">⚙</span><span class="tool-fname">${esc(fn.name || "")}</span>${tc.id ? `<span class="tool-desc-text">id: ${esc(tc.id.slice(0, 20))}</span>` : ""}<span class="tool-arrow">▼</span></div><div class="tool-card-body">${argsHtml}</div></div>`;
    }
    html += '</div></div>';
  }

  if (resp.finish) {
    html += `<div class="finish-info">finish_reason: ${esc(resp.finish)}</div>`;
  }

  html += '</div>';
  return html;
}

/* ── Headers ──────────────────────────────────────── */

function renderHeadersSection(title, headers) {
  if (!headers || !Object.keys(headers).length) return "";
  const rows = Object.entries(headers).map(([k, v]) =>
    `<tr><td>${esc(k)}</td><td>${esc(String(v))}</td></tr>`
  ).join("");
  return `<div class="collapse-section"><div class="collapse-head" onclick="this.parentElement.classList.toggle('closed')"><span class="collapse-arrow">▼</span>${title} (${Object.keys(headers).length})</div><div class="collapse-body"><table class="hdr-table">${rows}</table></div></div>`;
}

/* ═══════════════════════════════════════════════════
   用户管理
   ═══════════════════════════════════════════════════ */

function maskKey(k) {
  if (!k) return "-";
  return k.length <= 10 ? k : k.slice(0, 6) + "…" + k.slice(-4);
}

async function loadUsers() {
  const q = buildQuery({ q: state.userQuery, page: state.userPage });
  const p = await fetchJSON(`/admin/api/users?${q}`);
  const { items, pagination } = p;
  state.userPages = pagination.pages;
  document.getElementById("userPageInfo").textContent = `${pagination.page} / ${pagination.pages}`;
  document.getElementById("userMeta").textContent = `${pagination.total} 个用户`;
  document.getElementById("userPrevPage").disabled = pagination.page <= 1;
  document.getElementById("userNextPage").disabled = pagination.page >= pagination.pages;

  const tbody = document.getElementById("userRows");
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">暂无用户</td></tr>';
    return;
  }

  tbody.innerHTML = items.map(u => {
    return `<tr>
      <td>${esc(u.name)}</td>
      <td>-</td>
      <td>${fmtTimeFull(u.created_at)}</td>
      <td><div class="action-btns">
        <button class="ghost btn-sm" data-edit="${u.id}">编辑</button>
        <button class="ghost btn-sm btn-danger" data-del="${u.id}" data-name="${esc(u.name)}">删除</button>
      </div></td>
    </tr>`;
  }).join("");
}

// ── 搜索 ──
let _ust = null;
document.getElementById("userSearch").addEventListener("input", (e) => {
  clearTimeout(_ust);
  _ust = setTimeout(() => { state.userQuery = e.target.value.trim(); state.userPage = 1; loadUsers(); }, 320);
});

document.getElementById("userPrevPage").addEventListener("click", () => {
  if (state.userPage > 1) { state.userPage--; loadUsers(); }
});
document.getElementById("userNextPage").addEventListener("click", () => {
  if (state.userPage < state.userPages) { state.userPage++; loadUsers(); }
});

// ── Dialog ──

const dlg = document.getElementById("userDialog");
const dlgNodes = {
  title: document.getElementById("dialogTitle"),
  userId: document.getElementById("fieldUserId"),
  name: document.getElementById("fieldName"),
  password: document.getElementById("fieldPassword"),
  labelPassword: document.getElementById("labelPassword"),
  providers: document.getElementById("fieldProviders"),
};

function openDlg(title, data) {
  const isEdit = Boolean(data.id);
  dlgNodes.title.textContent = title;
  dlgNodes.userId.value = data.id || "";
  dlgNodes.name.value = data.name || "";
  dlgNodes.password.value = "";
  dlgNodes.labelPassword.textContent = isEdit ? "密码（留空不修改）" : "密码 *";
  // Render provider checkboxes
  const selectedIds = new Set(data.provider_ids || []);
  dlgNodes.providers.innerHTML = state.allProviders.map(p =>
    `<label><input type="checkbox" value="${esc(p.id)}" ${selectedIds.has(p.id) ? "checked" : ""} />${esc(p.name)} <small>(/${esc(p.prefix_path)})</small></label>`
  ).join("") || '<span style="color:var(--text-muted)">无 Provider，请先创建</span>';
  dlg.showModal();
}

document.getElementById("createUserBtn").addEventListener("click", () => openDlg("新建用户", {}));

document.getElementById("dialogCancelBtn").addEventListener("click", () => dlg.close());

document.getElementById("dialogSubmitBtn").addEventListener("click", async () => {
  const id = dlgNodes.userId.value;
  const providerIds = [...dlgNodes.providers.querySelectorAll("input:checked")].map(cb => cb.value);
  const body = {
    name: dlgNodes.name.value.trim(),
    provider_ids: providerIds,
  };
  const password = dlgNodes.password.value;
  if (password) body.password = password;
  if (!body.name) { alert("用户名不能为空"); return; }
  if (!id && !password) { alert("请设置密码"); return; }
  try {
    if (id) {
      await fetchJSON(`/admin/api/users/${id}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    } else {
      await fetchJSON("/admin/api/users", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    }
    dlg.close();
    await loadUsers();
  } catch (err) { alert("失败: " + err.message); }
});

document.getElementById("userRows").addEventListener("click", async (e) => {
  const editBtn = e.target.closest("[data-edit]");
  if (editBtn) {
    try { openDlg("编辑用户", await fetchJSON(`/admin/api/users/${editBtn.dataset.edit}`)); }
    catch (err) { alert("加载失败: " + err.message); }
    return;
  }
  const delBtn = e.target.closest("[data-del]");
  if (delBtn) {
    if (!confirm(`确认删除「${delBtn.dataset.name}」？`)) return;
    try { await fetchJSON(`/admin/api/users/${delBtn.dataset.del}`, { method: "DELETE" }); await loadUsers(); }
    catch (err) { alert("删除失败: " + err.message); }
  }
});

/* ═══════════════════════════════════════════════════
   Provider 管理
   ═══════════════════════════════════════════════════ */

async function loadProviders() {
  const data = await fetchJSON("/admin/api/providers");
  const items = data.items || [];
  state.allProviders = items;
  const tbody = document.getElementById("providerRows");
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted)">暂无 Provider</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(p => {
    const badge = p.enabled ? '<span class="badge ok">启用</span>' : '<span class="badge off">禁用</span>';
    return `<tr>
      <td>${esc(p.name)}</td>
      <td>/${esc(p.prefix_path)}</td>
      <td title="${esc(p.downstream_url)}">${esc(p.downstream_url.length > 40 ? p.downstream_url.slice(0, 37) + "…" : p.downstream_url)}</td>
      <td>${p.input_price || 0}</td>
      <td>${p.output_price || 0}</td>
      <td>${badge}</td>
      <td>${esc(p.notes || "")}</td>
      <td><div class="action-btns">
        <button class="ghost btn-sm" data-prov-edit="${p.id}">编辑</button>
        <button class="ghost btn-sm btn-danger" data-prov-del="${p.id}" data-prov-name="${esc(p.name)}">删除</button>
      </div></td>
    </tr>`;
  }).join("");
}

// ── Provider Dialog ──

const provDlg = document.getElementById("providerDialog");
const provNodes = {
  title: document.getElementById("provDialogTitle"),
  id: document.getElementById("provFieldId"),
  name: document.getElementById("provFieldName"),
  prefix: document.getElementById("provFieldPrefix"),
  url: document.getElementById("provFieldUrl"),
  apikey: document.getElementById("provFieldApikey"),
  inputPrice: document.getElementById("provFieldInputPrice"),
  outputPrice: document.getElementById("provFieldOutputPrice"),
  notes: document.getElementById("provFieldNotes"),
  enabled: document.getElementById("provFieldEnabled"),
};

function openProvDlg(title, data) {
  provNodes.title.textContent = title;
  provNodes.id.value = data.id || "";
  provNodes.name.value = data.name || "";
  provNodes.prefix.value = data.prefix_path || "";
  provNodes.url.value = data.downstream_url || "";
  provNodes.apikey.value = data.downstream_apikey || "";
  provNodes.inputPrice.value = data.input_price || 0;
  provNodes.outputPrice.value = data.output_price || 0;
  provNodes.notes.value = data.notes || "";
  provNodes.enabled.checked = data.enabled !== undefined ? Boolean(data.enabled) : true;
  provDlg.showModal();
}

document.getElementById("createProviderBtn").addEventListener("click", () => openProvDlg("新建 Provider", {}));

document.getElementById("provDialogCancelBtn").addEventListener("click", () => provDlg.close());

document.getElementById("provDialogSubmitBtn").addEventListener("click", async () => {
  const id = provNodes.id.value;
  const body = {
    name: provNodes.name.value.trim(),
    prefix_path: provNodes.prefix.value.trim(),
    downstream_url: provNodes.url.value.trim(),
    downstream_apikey: provNodes.apikey.value.trim(),
    input_price: parseFloat(provNodes.inputPrice.value) || 0,
    output_price: parseFloat(provNodes.outputPrice.value) || 0,
    notes: provNodes.notes.value.trim(),
    enabled: provNodes.enabled.checked,
  };
  if (!body.name || !body.prefix_path || !body.downstream_url) {
    alert("名称、前缀路径、Downstream URL 为必填项");
    return;
  }
  try {
    if (id) {
      await fetchJSON(`/admin/api/providers/${id}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    } else {
      await fetchJSON("/admin/api/providers", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    }
    provDlg.close();
    await loadProviders();
  } catch (err) { alert("失败: " + err.message); }
});

document.getElementById("providerRows").addEventListener("click", async (e) => {
  const editBtn = e.target.closest("[data-prov-edit]");
  if (editBtn) {
    try {
      const p = await fetchJSON(`/admin/api/providers/${editBtn.dataset.provEdit}`);
      openProvDlg("编辑 Provider", p);
    } catch (err) { alert("加载失败: " + err.message); }
    return;
  }
  const delBtn = e.target.closest("[data-prov-del]");
  if (delBtn) {
    if (!confirm(`确认删除 Provider「${delBtn.dataset.provName}」？`)) return;
    try {
      await fetchJSON(`/admin/api/providers/${delBtn.dataset.provDel}`, { method: "DELETE" });
      await loadProviders();
    } catch (err) { alert("删除失败: " + err.message); }
  }
});

/* ── 初始化 ───────────────────────────────────────── */

async function boot() {
  try {
    const session = await fetchJSON("/admin/api/session");
    state.currentUser = session.user;
    applyRole(session.user.role);
    if (session.user.role === "admin") {
      state.allProviders = (await fetchJSON("/admin/api/providers")).items || [];
    }
    await Promise.all([loadOverview(), loadLogs()]);
    if (session.user.role === "admin") {
      loadUsers();
      loadProviders();
    }
  } catch (err) {
    if (err.message && err.message.includes("登录")) return;
    console.error("boot error:", err);
  }
}

boot();
setInterval(loadOverview, 15000);