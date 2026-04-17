"use strict";

// --- Settings: custom status labels -----------------------------------------

const STATUS_KEYS = ["red", "yellow", "green", "vova_only", "free"];
const DEFAULT_LABELS = {
  red:       "Нужна тёща",
  yellow:    "Передача дочки",
  green:     "Вова с дочкой",
  vova_only: "Наташа с дочкой",
  free:      "Свободно у обоих",
};
const LABEL_HINTS = {
  red:       "оба работают, у Вовы событие после 20:00",
  yellow:    "оба работают, но Вова освобождается до 20:00",
  green:     "Наташа на смене, у Вовы нет работы",
  vova_only: "Вова работает, Наташа дома",
  free:      "у обоих свободный день",
};
const LABELS_KEY = "tcrnv:labels";

function loadLabels() {
  try {
    const raw = localStorage.getItem(LABELS_KEY);
    if (!raw) return { ...DEFAULT_LABELS };
    const stored = JSON.parse(raw);
    return { ...DEFAULT_LABELS, ...stored };
  } catch {
    return { ...DEFAULT_LABELS };
  }
}

function saveLabels(labels) {
  // Сохраняем только не-дефолтные значения
  const overrides = {};
  for (const k of STATUS_KEYS) {
    if (labels[k] && labels[k] !== DEFAULT_LABELS[k]) overrides[k] = labels[k];
  }
  if (Object.keys(overrides).length) {
    localStorage.setItem(LABELS_KEY, JSON.stringify(overrides));
  } else {
    localStorage.removeItem(LABELS_KEY);
  }
}

let currentLabels = { ...DEFAULT_LABELS };
let lastPayload = null;

// --- Settings: per-day availability (canSit) -------------------------------
// Хранит явные отметки "Вова может посидеть в этот день" (взял/возьмёт отгул).
// По умолчанию считается: если есть смена Наташи и Вова не отметил "могу",
// то Вова на работе → день требует решения (красный).

const AVAIL_KEY = "tcrnv:availability";
let availability = {}; // { "YYYY-MM-DD": true }

function loadAvailability() {
  try {
    const raw = localStorage.getItem(AVAIL_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function saveAvailability() {
  // Храним только true-значения, чтобы файл был компактным
  const compact = {};
  for (const [k, v] of Object.entries(availability)) {
    if (v === true) compact[k] = true;
  }
  if (Object.keys(compact).length) {
    localStorage.setItem(AVAIL_KEY, JSON.stringify(compact));
  } else {
    localStorage.removeItem(AVAIL_KEY);
  }
}

// Пересчитывает статус с учётом отметки "могу посидеть".
// Backend выставил "наивный" статус, считая что Вова свободен если нет событий.
// Здесь мы корректируем: green только когда есть явное "Могу".
function effectiveStatus(day) {
  const hasNatasha = day.natasha.length > 0;
  if (!hasNatasha) {
    return day.vova.length ? "vova_only" : "free";
  }
  // Наташа работает
  const hasHard = day.overlaps.some(o => o.hard);
  if (hasHard) return "red";
  if (day.overlaps.length) return "yellow";
  // Нет пересечений: green только если Вова отметил "могу посидеть"
  return availability[day.date] === true ? "green" : "red";
}

// --- Crypto helpers ---------------------------------------------------------

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(password, salt, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptPayload(blob, password) {
  const salt = b64ToBytes(blob.salt);
  const iv = b64ToBytes(blob.iv);
  const ciphertext = b64ToBytes(blob.ciphertext);
  const key = await deriveKey(password, salt, blob.iterations);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plain));
}

// --- DOM helpers ------------------------------------------------------------

const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") node[k] = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
};

const DOW_RU_SHORT = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"];
const DOW_RU_FULL = ["понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье"];
const MONTH_RU_NOM = [
  "январь", "февраль", "март", "апрель", "май", "июнь",
  "июль", "август", "сентябрь", "октябрь", "ноябрь", "декабрь",
];
const MONTH_RU_GEN = [
  "января", "февраля", "марта", "апреля", "мая", "июня",
  "июля", "августа", "сентября", "октября", "ноября", "декабря",
];

function parseDate(iso) {
  const [y, m, d] = iso.split("-").map(Number);
  return { y, m, d };
}

function formatGenerated(iso) {
  const dt = new Date(iso);
  return dt.toLocaleString("ru-RU", {
    timeZone: "Asia/Almaty",
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function formatDuration(minutes) {
  if (minutes < 60) return `${minutes} мин`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return m ? `${h} ч ${m} мин` : `${h} ч`;
}

// --- Tooltip ----------------------------------------------------------------

const tooltip = () => $("#tooltip");

function buildTooltipContent(day) {
  const { y, m, d } = parseDate(day.date);
  const dayLabel = `${d} ${MONTH_RU_GEN[m - 1]}, ${DOW_RU_FULL[day.weekday]}`;

  const status = effectiveStatus(day);
  const statusText = currentLabels[status] || DEFAULT_LABELS[status] || status;
  const hasNatasha = day.natasha.length > 0;

  const children = [
    el("div", { class: "tt-date" },
      dayLabel,
      el("span", { class: `tt-status ${status}` }, statusText),
    ),
  ];

  // Переключатель «Могу/не могу посидеть» — только в дни смен Наташи.
  if (hasNatasha) {
    const canSit = availability[day.date] === true;
    const toggleBtn = el("button", {
      type: "button",
      class: "tt-can-sit" + (canSit ? " active" : ""),
      "data-date": day.date,
      onclick: (e) => {
        e.stopPropagation();
        if (canSit) delete availability[day.date];
        else availability[day.date] = true;
        saveAvailability();
        // Перерисовываем дашборд, тултип останется открытым на той же ячейке
        reapplyLabels();
        // Перерисовываем сам тултип с обновлённым состоянием
        const cell = document.querySelector(`.cell[data-date="${day.date}"]`);
        if (cell) showTooltip(day, cell.getBoundingClientRect(), true);
      },
    },
      canSit ? "✓ Могу посидеть (отгул)" : "Отметить «Могу посидеть»",
    );
    children.push(el("div", { class: "tt-section" }, toggleBtn));
  }

  if (day.natasha.length === 0 && day.vova.length === 0) {
    children.push(el("div", { class: "tt-section" },
      el("div", { class: "tt-label" }, "У обоих свободный день")
    ));
    return children;
  }

  if (day.natasha.length) {
    const eventsBox = el("div", {});
    for (const s of day.natasha) {
      eventsBox.appendChild(el("div", { class: "tt-event" },
        el("span", { class: "tt-time" }, `${s.start}–${s.end}`),
        el("span", { class: "tt-name" }, s.summary || "Работа"),
      ));
    }
    children.push(el("div", { class: "tt-section" },
      el("div", { class: "tt-label n" },
        el("span", { class: "pin" }), "Наташа",
      ),
      eventsBox,
    ));
  }

  if (day.vova.length) {
    const eventsBox = el("div", {});
    for (const v of day.vova) {
      eventsBox.appendChild(el("div", {
        class: "tt-event" + (v.transparent ? " transparent" : ""),
      },
        el("span", { class: "tt-time" }, `${v.start}–${v.end}`),
        el("span", { class: "tt-name" }, v.summary || "(без названия)"),
      ));
    }
    children.push(el("div", { class: "tt-section" },
      el("div", { class: "tt-label v" },
        el("span", { class: "pin" }), "Вова",
      ),
      eventsBox,
    ));
  }

  if (day.overlaps.length) {
    const overlapsBox = el("div", {});
    for (const o of day.overlaps) {
      const label = o.hard ? "🟥 Жёсткое пересечение" : "🟨 Мягкое пересечение";
      overlapsBox.appendChild(el("div", {
        class: "tt-overlap" + (o.hard ? " hard" : ""),
      },
        el("div", { class: "tt-overlap-head" }, label),
        el("div", {}, `${o.start}–${o.end} · ${formatDuration(o.minutes)}`),
        el("div", {}, `Событие Вовы: «${o.vova_event || "—"}»`),
      ));
    }
    children.push(el("div", { class: "tt-section" }, overlapsBox));
  }

  return children;
}

let tooltipPinned = false;

function showTooltip(day, anchorRect, pinned = false) {
  const tt = tooltip();
  tt.innerHTML = "";
  for (const node of buildTooltipContent(day)) tt.appendChild(node);
  if (pinned) tooltipPinned = true;

  // Делаем видимым, чтобы измерить размеры
  tt.classList.add("visible");
  const ttRect = tt.getBoundingClientRect();
  const padding = 8;

  // По умолчанию — справа от ячейки, выровнено по верху
  let left = anchorRect.right + padding;
  let top = anchorRect.top;

  // Если не помещается справа — слева
  if (left + ttRect.width > window.innerWidth - padding) {
    left = anchorRect.left - ttRect.width - padding;
  }
  // Если не помещается слева — снизу/сверху по центру
  if (left < padding) {
    left = Math.max(padding, Math.min(
      anchorRect.left + anchorRect.width / 2 - ttRect.width / 2,
      window.innerWidth - ttRect.width - padding,
    ));
    top = anchorRect.bottom + padding;
    if (top + ttRect.height > window.innerHeight - padding) {
      top = anchorRect.top - ttRect.height - padding;
    }
  }
  // Не вылезаем снизу
  if (top + ttRect.height > window.innerHeight - padding) {
    top = window.innerHeight - ttRect.height - padding;
  }
  if (top < padding) top = padding;

  tt.style.left = `${left}px`;
  tt.style.top = `${top}px`;
}

function hideTooltip(force = false) {
  if (tooltipPinned && !force) return;
  tooltip().classList.remove("visible");
  tooltipPinned = false;
}

// --- Calendar render --------------------------------------------------------

function makeCell(day, todayIso) {
  const { d } = parseDate(day.date);
  const isWeekend = day.weekday >= 5;
  const isToday = day.date === todayIso;
  const hasMarks = day.natasha.length > 0 || day.vova.length > 0;

  const status = effectiveStatus(day);
  const classes = ["cell", "has-data", status];
  if (availability[day.date] === true) classes.push("can-sit");
  if (isWeekend) classes.push("weekend");
  if (isToday) classes.push("today");

  const marks = el("div", { class: "marks" });
  if (day.natasha.length) marks.appendChild(el("span", { class: "mark n" }));
  if (day.vova.length) marks.appendChild(el("span", { class: "mark v" }));

  const cell = el("div", { class: classes.join(" "), "data-date": day.date },
    String(d),
    hasMarks ? marks : null,
  );

  cell.addEventListener("mouseenter", () => {
    if (!tooltipPinned) showTooltip(day, cell.getBoundingClientRect(), false);
  });
  cell.addEventListener("mouseleave", () => hideTooltip(false));
  cell.addEventListener("click", (e) => {
    e.stopPropagation();
    showTooltip(day, cell.getBoundingClientRect(), true);
  });

  return cell;
}

// Состояние навигации по месяцам
let monthGroups = [];     // [{ y, m, days: [...] }, ...]
let currentMonthIdx = 0;
let cachedTodayIso = null;

function renderMonth(idx) {
  const root = $("#months");
  root.innerHTML = "";
  if (idx < 0 || idx >= monthGroups.length) return;

  currentMonthIdx = idx;
  const { y, m, days: monthDays } = monthGroups[idx];

  $("#month-title").textContent = `${MONTH_RU_NOM[m - 1]} ${y}`;
  $("#prev-month").disabled = idx === 0;
  $("#next-month").disabled = idx === monthGroups.length - 1;

  const monthBox = el("div", { class: "month" });

  const wkRow = el("div", { class: "weekday-row" });
  for (const w of DOW_RU_SHORT) wkRow.appendChild(el("span", {}, w));
  monthBox.appendChild(wkRow);

  const grid = el("div", { class: "grid" });

  // Пустые ячейки до первого дня месяца
  // (определяем weekday первого дня этого месяца, не из данных)
  const firstOfMonth = new Date(y, m - 1, 1);
  const firstWeekday = (firstOfMonth.getDay() + 6) % 7; // 0 = понедельник
  for (let i = 0; i < firstWeekday; i++) {
    grid.appendChild(el("div", { class: "cell empty" }));
  }

  const dataByDayNum = new Map();
  for (const day of monthDays) dataByDayNum.set(parseDate(day.date).d, day);

  const daysInMonth = new Date(y, m, 0).getDate();
  for (let dayNum = 1; dayNum <= daysInMonth; dayNum++) {
    const dayData = dataByDayNum.get(dayNum);
    if (dayData) {
      grid.appendChild(makeCell(dayData, cachedTodayIso));
    } else {
      // День вне горизонта (прошлое или после horizon_days)
      const dummyDate = new Date(y, m - 1, dayNum);
      const wd = (dummyDate.getDay() + 6) % 7;
      const dummyIso = dummyDate.toLocaleDateString("sv-SE", { timeZone: "Asia/Almaty" });
      const cls = ["cell", "out-of-range"];
      if (wd >= 5) cls.push("weekend");
      if (dummyIso === cachedTodayIso) cls.push("today");
      grid.appendChild(el("div", { class: cls.join(" ") }, String(dayNum)));
    }
  }

  monthBox.appendChild(grid);
  root.appendChild(monthBox);
  hideTooltip();
}

function setupMonths(days, todayIso) {
  cachedTodayIso = todayIso;

  // Группируем дни по году+месяцу
  const groups = new Map();
  for (const day of days) {
    const { y, m } = parseDate(day.date);
    const key = `${y}-${m}`;
    if (!groups.has(key)) groups.set(key, { y, m, days: [] });
    groups.get(key).days.push(day);
  }
  monthGroups = [...groups.values()];

  // Стартуем с месяца, в котором сегодняшний день
  const todayY = parseInt(todayIso.slice(0, 4), 10);
  const todayM = parseInt(todayIso.slice(5, 7), 10);
  let startIdx = monthGroups.findIndex(g => g.y === todayY && g.m === todayM);
  if (startIdx === -1) startIdx = 0;

  $("#month-nav").hidden = false;
  renderMonth(startIdx);
}

function renderLegend() {
  const legend = $("#legend");
  if (!legend) return;
  legend.innerHTML = "";
  for (const k of STATUS_KEYS) {
    legend.appendChild(el("span", { class: "item" },
      el("span", { class: `dot ${k}` }),
      currentLabels[k] || DEFAULT_LABELS[k],
    ));
  }
}

function renderSummary(days) {
  const counts = Object.fromEntries(STATUS_KEYS.map(k => [k, 0]));
  for (const d of days) {
    const s = effectiveStatus(d);
    if (counts[s] !== undefined) counts[s]++;
  }
  const summary = $("#summary");
  summary.innerHTML = "";
  for (const k of STATUS_KEYS) {
    summary.appendChild(el("div", { class: `card ${k}` },
      el("div", { class: "num" }, String(counts[k])),
      el("div", { class: "lbl" }, currentLabels[k] || DEFAULT_LABELS[k]),
    ));
  }
}

function renderDashboard(payload) {
  lastPayload = payload;
  $("#generated-at").textContent = formatGenerated(payload.generated_at);
  $("#horizon").textContent = String(payload.horizon_days);
  $("#tz").textContent = payload.tz;

  renderLegend();
  renderSummary(payload.days);

  const todayIso = new Date().toLocaleDateString("sv-SE", { timeZone: "Asia/Almaty" });
  setupMonths(payload.days, todayIso);
}

// Перерисовка после изменения настроек (без повторной расшифровки)
function reapplyLabels() {
  if (!lastPayload) return;
  renderLegend();
  renderSummary(lastPayload.days);
  if (monthGroups.length) renderMonth(currentMonthIdx);
}

// --- Auth flow --------------------------------------------------------------

const STORAGE_KEY = "tcrnv:password";
let cachedBlob = null;

async function loadBlob() {
  if (cachedBlob) return cachedBlob;
  const resp = await fetch("data.enc.json", { cache: "no-store" });
  if (!resp.ok) throw new Error("Не удалось загрузить data.enc.json");
  cachedBlob = await resp.json();
  return cachedBlob;
}

async function tryUnlock(password) {
  const blob = await loadBlob();
  return decryptPayload(blob, password);
}

async function showApp(payload) {
  $("#gate").hidden = true;
  $("#app").hidden = false;
  renderDashboard(payload);
}

function showGate() {
  $("#gate").hidden = false;
  $("#app").hidden = true;
  $("#gate-error").hidden = true;
  $("#password").value = "";
  $("#password").focus();
}

// --- Settings modal --------------------------------------------------------

function openSettings() {
  const form = $("#settings-form");
  form.innerHTML = "";
  for (const k of STATUS_KEYS) {
    const inputId = `lbl-${k}`;
    form.appendChild(el("div", { class: "settings-row" },
      el("label", { for: inputId },
        el("span", { class: `swatch dot ${k}` }),
        `${DEFAULT_LABELS[k]} — ${LABEL_HINTS[k]}`,
      ),
      el("input", {
        type: "text",
        id: inputId,
        "data-key": k,
        value: currentLabels[k] || DEFAULT_LABELS[k],
        maxlength: "60",
      }),
    ));
  }
  $("#settings-modal").hidden = false;
}

function closeSettings() {
  $("#settings-modal").hidden = true;
}

function init() {
  currentLabels = loadLabels();
  availability = loadAvailability();

  // Подключаем обработчик СИНХРОННО — кнопка реагирует мгновенно.
  $("#gate-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pass = $("#password").value;
    const status = $("#gate-status");
    const button = $("#gate-form button");
    button.disabled = true;
    status.textContent = "Проверяю…";
    $("#gate-error").hidden = true;
    console.log("[gate] trying password, length =", pass.length);
    try {
      const payload = await tryUnlock(pass);
      sessionStorage.setItem(STORAGE_KEY, pass);
      status.textContent = "";
      await showApp(payload);
    } catch (err) {
      console.error("[gate] decrypt failed:", err, "input length was", pass.length);
      status.textContent = "";
      let msg = "Неверный пароль";
      if (err && err.name && err.name !== "OperationError") {
        msg = `Ошибка: ${err.message || err.name}`;
      }
      if (pass.length > 6) {
        msg += " (похоже, менеджер паролей дописал лишнее — введите вручную)";
      }
      $("#gate-error").textContent = msg;
      $("#gate-error").hidden = false;
      $("#password").value = "";
      $("#password").focus();
    } finally {
      button.disabled = false;
    }
  });

  $("#lock-btn")?.addEventListener("click", () => {
    sessionStorage.removeItem(STORAGE_KEY);
    showGate();
  });

  // Кнопки настроек
  $("#settings-btn")?.addEventListener("click", (e) => {
    e.stopPropagation();
    openSettings();
  });
  $("#settings-cancel")?.addEventListener("click", closeSettings);
  $("#settings-modal")?.addEventListener("click", (e) => {
    // Клик по тёмной подложке — закрыть
    if (e.target === $("#settings-modal")) closeSettings();
  });
  $("#settings-save")?.addEventListener("click", () => {
    const next = { ...currentLabels };
    for (const k of STATUS_KEYS) {
      const input = document.getElementById(`lbl-${k}`);
      if (input) {
        const v = input.value.trim();
        next[k] = v || DEFAULT_LABELS[k];
      }
    }
    currentLabels = next;
    saveLabels(currentLabels);
    closeSettings();
    reapplyLabels();
  });
  $("#settings-reset")?.addEventListener("click", () => {
    if (!confirm("Сбросить все названия к стандартным?")) return;
    currentLabels = { ...DEFAULT_LABELS };
    saveLabels(currentLabels);
    closeSettings();
    reapplyLabels();
  });

  // Скрываем липкий тултип при клике вне него (но не при клике внутри)
  document.addEventListener("click", (e) => {
    const tt = tooltip();
    if (tt.contains(e.target)) return;
    hideTooltip(true);
  });
  document.addEventListener("scroll", () => hideTooltip(true), true);

  // Кнопки навигации по месяцам
  $("#prev-month")?.addEventListener("click", (e) => {
    e.stopPropagation();
    if (currentMonthIdx > 0) renderMonth(currentMonthIdx - 1);
  });
  $("#next-month")?.addEventListener("click", (e) => {
    e.stopPropagation();
    if (currentMonthIdx < monthGroups.length - 1) renderMonth(currentMonthIdx + 1);
  });

  // Авто-разблокировка — асинхронно, в фоне.
  const saved = sessionStorage.getItem(STORAGE_KEY);
  if (saved) {
    tryUnlock(saved)
      .then(showApp)
      .catch(() => sessionStorage.removeItem(STORAGE_KEY));
  }
}

document.addEventListener("DOMContentLoaded", init);
