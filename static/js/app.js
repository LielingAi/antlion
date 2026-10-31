(function(){
"use strict";
const api = HP.api;
const { stixUrl, setToken } = HP;
const views = HP.views;
const { $, h, toast, esc, openDrawer, closeDrawer } = HP.ui;
/* 应用外壳 — 路由 / 导航 / 全局筛选 / 命令面板 / 生命周期 */

/* ---------- 信息架构: 分组导航 ---------- */
const NAV = [
  { group: "监控", items: [
    { id: "outcome", label: "战果", icon: "★", view: "viewOutcome" },
    { id: "situation", label: "态势", icon: "◉", view: "viewSituation" },
    { id: "events", label: "事件流", icon: "≡", view: "viewEventsGroup" },
  ]},
  { group: "指挥", items: [
    { id: "ops", label: "作战室", icon: "⚔", view: "viewOps" },
    { id: "tasking", label: "指挥台", icon: "⌘", view: "viewTasking" },
  ]},
  { group: "军械", items: [
    { id: "arsenal", label: "武器库", icon: "✦", view: "viewArsenal" },
  ]},
  { group: "调查", items: [
    { id: "investigate", label: "攻击者", icon: "⌖", view: "viewAttackers" },
    { id: "sessions", label: "会话卷宗", icon: "◔", view: "viewSessions" },
  ]},
  { group: "资产与情报", items: [
    { id: "fleet", label: "传感器", icon: "▤", view: "viewFleet" },
    { id: "intel", label: "情报", icon: "◆", view: "viewIntelGroup" },
  ]},
  { group: "研究", items: [
    { id: "experiments", label: "实验", icon: "⌁", view: "viewExperimentsGroup" },
  ]},
  { group: "系统", items: [
    { id: "config", label: "配置", icon: "⚙", view: "viewConfig" },
  ]},
];
// 旧路由 → 新目的地 (深链接兼容)
const LEGACY = {
  live: "events/tail", requests: "events/requests", actions: "events/actions",
  attribution: "intel/actors", metrics: "situation",
  summary: "experiments/summary", compare: "experiments/compare",
  bandit: "experiments/bandit", trials: "experiments/trials", runs: "experiments/runs",
};
const ALL_ITEMS = NAV.flatMap((g) => g.items);
const TITLES = Object.fromEntries(ALL_ITEMS.map((i) => [i.id, i.label]));

const state = {
  page: null, view: null, auto: localStorage.getItem("hp_auto") !== "0",
  range: localStorage.getItem("hp_range") || "24h",
  run: localStorage.getItem("hp_run") || "",
  me: null, timer: null,
};

/* ---------- 导航渲染 ---------- */
function renderNav() {
  const nav = $("#sidenav");
  nav.innerHTML = "";
  for (const g of NAV) {
    nav.append(h("div", { class: "nav-group" }, g.group));
    for (const it of g.items) {
      nav.append(h("div", {
        class: "nav-item" + (state.page === it.id ? " active" : ""),
        onclick: () => { location.hash = `#/${it.id}`; $("#app").classList.remove("nav-open"); },
      }, h("span", { class: "ico" }, it.icon), h("span", { class: "nav-label" }, it.label)));
    }
  }
}

/* ---------- 生命周期 ---------- */
async function mount() {
  let hash = (location.hash.replace(/^#\/?/, "") || "outcome");
  if (LEGACY[hash]) { location.replace("#/" + LEGACY[hash]); hash = LEGACY[hash]; }
  // 实体路由: #/e/<type>/<id> — 统一调查对象, 跨页游走的落点
  let entity = null;
  if (hash.startsWith("e/")) {
    const [, etype, ...rest] = hash.split("/");
    entity = { type: etype, id: decodeURIComponent(rest.join("/")) };
  }
  const [gid, tab] = hash.split("/");
  const item = ALL_ITEMS.find((i) => i.id === gid) ||
    (entity ? { id: "entity", label: "调查对象", view: "viewEntity" } : ALL_ITEMS[0]);
  state.page = item.id;
  renderNav();
  $("#crumbs").innerHTML = `<b>${esc(item.label)}</b>`;
  document.title = `${item.label} · Agent 捕获反制`;

  state.view?.dispose?.();
  state.view = null;
  const content = $("#content");
  content.innerHTML = "";
  const ctx = { run: () => state.run, tab, entity };
  try {
    const v = await views[item.view](ctx);
    state.view = v;
    content.append(v.root);
  } catch (e) {
    if (e.code === 401) { showLogin(); return; }
    content.append(h("div", { class: "empty" }, `加载失败: ${e.message}`));
  }
}

async function refresh() {
  if (!state.view?.reload) return;
  try { await state.view.reload(); }
  catch (e) { if (e.code === 401) showLogin(); }
}

function armAuto() {
  clearInterval(state.timer);
  if (!state.auto) return;
  state.timer = setInterval(() => {
    if (document.hidden) return;
    refresh();
    if (state.page === "situation") loadHealth();
  }, 8000);
}

/* ---------- 顶栏 / 筛选 ---------- */
async function loadRuns() {
  try {
    const runs = await api.runs();
    const sel = $("#filter-run");
    sel.innerHTML = "";
    sel.append(h("option", { value: "" }, "全部运行"));
    for (const r of runs) {
      sel.append(h("option", { value: r.run_id }, `${r.mock ? "[模拟] " : ""}${r.run_id}`));
    }
    if (state.run) sel.value = state.run;
    sel.onchange = (e) => {
      state.run = e.target.value; localStorage.setItem("hp_run", state.run); refresh();
    };
  } catch (_) {}
}

async function loadHealth() {
  try {
    const s = await api.situation();
    $("#side-health").textContent =
      `24h ${s.total_24h} · 触雷 ${s.canary_24h} · 节点 ${s.sensors_online}/${s.sensors_total}`;
  } catch (_) {}
}

/* ---------- 命令面板 ---------- */
const TAB_NAV = [
  ["事件流 · 实时尾流", "events/tail"], ["事件流 · 请求日志", "events/requests"],
  ["事件流 · 动作流水", "events/actions"], ["情报 · 情报分级", "intel/graded"],
  ["情报 · 操作者归因", "intel/actors"], ["实验 · 试验明细", "experiments/trials"],
  ["实验 · 汇总指标", "experiments/summary"], ["实验 · 模型差分", "experiments/compare"],
  ["实验 · 演化实验", "experiments/bandit"], ["实验 · 运行记录", "experiments/runs"],
];
function paletteItems() {
  const navItems = [
    ...ALL_ITEMS.map((i) => ({
      label: i.label, hint: `跳转 · ${i.id}`, act: () => { location.hash = `#/${i.id}`; } })),
    ...TAB_NAV.map(([label, path]) => ({
      label, hint: "跳转 · " + path, act: () => { location.hash = `#/${path}`; } })),
  ];
  const actions = [
    { label: "刷新当前页", hint: "动作", act: () => refresh() },
    { label: "导出 STIX 情报", hint: "动作", act: () => window.open(stixUrl(state.run), "_blank") },
    { label: "切换自动刷新", hint: "动作", act: () => { $("#chk-auto").click(); } },
    { label: "退出登录", hint: "动作", act: () => doLogout() },
  ];
  return [...navItems, ...actions];
}
let pSel = 0, pList = [];
function openPalette() {
  $("#palette").hidden = false;
  $("#palette-input").value = "";
  renderPalette("");
  $("#palette-input").focus();
}
function closePalette() { $("#palette").hidden = true; }
function renderPalette(q) {
  const all = paletteItems();
  pList = q ? all.filter((i) => (i.label + i.hint).toLowerCase().includes(q.toLowerCase())) : all;
  pSel = 0;
  const box = $("#palette-list");
  box.innerHTML = "";
  pList.slice(0, 12).forEach((it, i) => {
    box.append(h("div", { class: "palette-item" + (i === pSel ? " sel" : ""),
      onclick: () => { closePalette(); it.act(); } },
      h("span", {}, it.label), h("span", { class: "hint" }, it.hint)));
  });
}

/* ---------- 登录 ---------- */
function showLogin() {
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#login-user").focus();
}
function showApp() { $("#login").hidden = true; $("#app").hidden = false; }

async function doLogin(u, p) {
  $("#login-err").textContent = "";
  try {
    const r = await api.login(u, p);
    setToken("");
    state.me = r;
    showApp();
    await boot();
  } catch (e) {
    $("#login-err").textContent = e.code === 401 ? "用户名或密码错误" : "登录失败: " + e.message;
  }
}
async function doLogout() {
  try { await api.logout(); } catch (_) {}
  setToken("");
  sessionStorage.clear();
  location.href = "/";
}

/* ---------- 启动 ---------- */
async function boot() {
  try {
    state.me = await api.me();
  } catch (e) {
    if (e.code === 401) { showLogin(); return; }
    showLogin(); return;
  }
  $("#user-name").textContent = state.me.user || state.me.role;
  showApp();   /* 会话有效直达 (刷新/深链接) — 唯一 unhide 入口在 doLogin 会导致刷新永黑 */
  $("#user-avatar").textContent = (state.me.user || "?")[0].toUpperCase();
  $("#user-box").onclick = () => openDrawer("账户", h("div", {},
    h("div", { class: "kv" },
      h("div", { class: "k" }, "用户"), h("div", { class: "v" }, state.me.user || "-"),
      h("div", { class: "k" }, "角色"), h("div", { class: "v" }, state.me.role),
      h("div", { class: "k" }, "认证"), h("div", { class: "v" }, state.me.auth)),
    h("button", { class: "btn", onclick: doLogout }, "退出登录")));
  await loadRuns();
  loadHealth();
  await mount();
}

window.addEventListener("hashchange", () => { mount(); });
/* 会话过期 (hive 重启 → 内存 SESSIONS 清空) — 任何 API 401 全局弹登录页,
   避免 view 内部 catch 静默后列表无声消失 */
window.addEventListener("hp:expired", () => { setToken(""); showLogin(); });
window.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault(); openPalette();
  } else if (e.key === "Escape") { closePalette(); closeDrawer(); }
  else if (!$("#palette").hidden) {
    if (e.key === "ArrowDown") { pSel = Math.min(pSel + 1, pList.length - 1); renderPalette($("#palette-input").value); }
    if (e.key === "ArrowUp") { pSel = Math.max(pSel - 1, 0); renderPalette($("#palette-input").value); }
    if (e.key === "Enter" && pList[pSel]) { closePalette(); pList[pSel].act(); }
  }
});
$("#palette-input")?.addEventListener("input", (e) => renderPalette(e.target.value));
$("#palette")?.addEventListener("click", (e) => { if (e.target.id === "palette") closePalette(); });
$("#btn-palette").onclick = openPalette;
$("#btn-refresh").onclick = () => { refresh(); loadHealth(); };
$("#btn-stix").onclick = () => window.open(stixUrl(state.run), "_blank");
$("#btn-collapse").onclick = () => $("#app").classList.toggle("collapsed");
$("#btn-menu").onclick = () => $("#app").classList.toggle("nav-open");
$("#scrim").onclick = () => $("#app").classList.remove("nav-open");
window.addEventListener("resize", () => {
  if (window.innerWidth > 820) $("#app").classList.remove("nav-open");
  // 超宽屏: 内容上限随视口放大 (1080p 以上再放宽), 避免大片留白
  const w = window.innerWidth;
  const cap = w >= 2200 ? "none" : w >= 1700 ? "1760px" : "1720px";
  document.documentElement.style.setProperty("--content-max", cap);
});
window.dispatchEvent(new Event("resize"));
$("#chk-auto").checked = state.auto;
$("#chk-auto").onchange = (e) => {
  state.auto = e.target.checked; localStorage.setItem("hp_auto", state.auto ? "1" : "0"); armAuto();
};
$("#filter-range").value = state.range;
$("#filter-range").onchange = (e) => {
  state.range = e.target.value; localStorage.setItem("hp_range", state.range); refresh();
};
$("#login-form").addEventListener("submit", (e) => {
  e.preventDefault();
  doLogin($("#login-user").value, $("#login-pass").value);
});

armAuto();
boot();
})();
