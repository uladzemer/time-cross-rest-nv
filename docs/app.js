"use strict";

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
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
};

const DOW_RU = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"];
const MONTH_RU = [
  "янв", "фев", "мар", "апр", "мая", "июн",
  "июл", "авг", "сен", "окт", "ноя", "дек",
];

function formatDate(iso) {
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

// --- Render -----------------------------------------------------------------

function renderDay(day, todayIso) {
  const { y, m, d } = formatDate(day.date);
  const isWeekend = day.weekday >= 5;
  const isToday = day.date === todayIso;

  const classes = ["day", day.status];
  if (isWeekend) classes.push("weekend");
  if (isToday) classes.push("today");

  const dateBox = el("div", { class: "date" },
    el("span", { class: "dow" }, DOW_RU[day.weekday] + (isToday ? " · сегодня" : "")),
    el("span", { class: "num" }, String(d)),
    el("span", { class: "month" }, MONTH_RU[m - 1]),
  );

  const bodyChildren = [];

  if (day.natasha.length === 0 && day.vova.length === 0) {
    bodyChildren.push(el("div", { class: "empty-day" }, "Свободный день у обоих"));
  }

  if (day.natasha.length) {
    const items = day.natasha.map(s =>
      el("span", { class: "item" },
        el("span", { class: "time" }, `${s.start}–${s.end}`),
        s.summary || "Работа",
      )
    );
    bodyChildren.push(el("div", { class: "row" },
      el("span", { class: "who" }, "Наташа"), ...items,
    ));
  }

  if (day.vova.length) {
    const items = day.vova.map(v =>
      el("span", { class: "item" + (v.transparent ? " transparent" : "") },
        el("span", { class: "time" }, `${v.start}–${v.end}`),
        v.summary || "(без названия)",
      )
    );
    bodyChildren.push(el("div", { class: "row" },
      el("span", { class: "who" }, "Вова"), ...items,
    ));
  }

  for (const ov of day.overlaps) {
    const cls = "overlap " + (ov.hard ? "hard" : "soft");
    const labelText = ov.hard ? "🟥 жёсткое" : "🟨 мягкое";
    const dur = ov.minutes >= 60
      ? `${Math.floor(ov.minutes / 60)}ч ${ov.minutes % 60 ? (ov.minutes % 60) + "м" : ""}`.trim()
      : `${ov.minutes} мин`;
    bodyChildren.push(el("div", { class: cls },
      el("span", { class: "label" }, labelText),
      `${ov.start}–${ov.end} (${dur}) — «${ov.vova_event || "событие"}»`,
    ));
  }

  return el("div", { class: classes.join(" ") }, dateBox, el("div", { class: "body" }, ...bodyChildren));
}

function renderDashboard(payload) {
  $("#generated-at").textContent = formatGenerated(payload.generated_at);
  $("#horizon").textContent = String(payload.horizon_days);
  $("#tz").textContent = payload.tz;

  const counts = { red: 0, yellow: 0, green: 0, free: 0 };
  for (const d of payload.days) counts[d.status]++;

  const summary = $("#summary");
  summary.innerHTML = "";
  const cards = [
    { key: "red",    num: counts.red,    lbl: "жёстких дней (нужна тёща)" },
    { key: "yellow", num: counts.yellow, lbl: "мягких дней (передача)" },
    { key: "green",  num: counts.green,  lbl: "Вова дома с дочкой" },
    { key: "free",   num: counts.free,   lbl: "свободных дней" },
  ];
  for (const c of cards) {
    summary.appendChild(el("div", { class: `card ${c.key}` },
      el("div", { class: "num" }, String(c.num)),
      el("div", { class: "lbl" }, c.lbl),
    ));
  }

  const todayIso = new Date().toLocaleDateString("sv-SE", { timeZone: "Asia/Almaty" });
  const days = $("#days");
  days.innerHTML = "";
  for (const d of payload.days) days.appendChild(renderDay(d, todayIso));
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
  const payload = await decryptPayload(blob, password);
  return payload;
}

async function showApp(payload) {
  $("#gate").hidden = true;
  $("#app").hidden = false;
  renderDashboard(payload);
}

function showGate(errorMsg) {
  $("#gate").hidden = false;
  $("#app").hidden = true;
  const err = $("#gate-error");
  if (errorMsg) {
    err.textContent = errorMsg;
    err.hidden = false;
  } else {
    err.hidden = true;
  }
  $("#password").value = "";
  $("#password").focus();
}

async function init() {
  const saved = sessionStorage.getItem(STORAGE_KEY);
  if (saved) {
    try {
      const payload = await tryUnlock(saved);
      await showApp(payload);
      return;
    } catch {
      sessionStorage.removeItem(STORAGE_KEY);
    }
  }

  $("#gate-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pass = $("#password").value;
    const status = $("#gate-status");
    const button = $("#gate-form button");
    button.disabled = true;
    status.textContent = "Проверяю...";
    $("#gate-error").hidden = true;
    try {
      const payload = await tryUnlock(pass);
      sessionStorage.setItem(STORAGE_KEY, pass);
      status.textContent = "";
      await showApp(payload);
    } catch (err) {
      status.textContent = "";
      $("#gate-error").textContent = "Неверный пароль";
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
}

document.addEventListener("DOMContentLoaded", init);
