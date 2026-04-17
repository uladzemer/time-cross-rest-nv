"""
Скачивает iCal-фиды Наташи и Вовы, считает пересечения смен с событиями,
классифицирует каждый день и публикует зашифрованный data.enc.json в docs/.

Шифрование: AES-GCM, ключ через PBKDF2-HMAC-SHA256 (200_000 итераций) от пароля.
Расшифровка происходит в браузере через Web Crypto API.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

# --- Settings -----------------------------------------------------------------

NATASHA_ICS = (
    "https://calendar.google.com/calendar/ical/"
    "77e3acf37c0782d94fddf377eff85c58cecf3b6448ba3b07c7f3e6f89f169f87"
    "%40group.calendar.google.com/public/basic.ics"
)
VOVA_ICS = (
    "https://calendar.google.com/calendar/ical/"
    "ortamanager%40gmail.com/public/basic.ics"
)

DISPLAY_TZ = ZoneInfo("Asia/Almaty")
HORIZON_DAYS = 60
KID_BEDTIME_HOUR = 20
PBKDF2_ITERATIONS = 200_000

OUT_DIR = Path(__file__).parent / "docs"


# --- iCal parsing -------------------------------------------------------------


@dataclass
class Event:
    summary: str
    start: datetime
    end: datetime
    transparent: bool
    uid: str

    @property
    def start_local(self) -> datetime:
        return self.start.astimezone(DISPLAY_TZ)

    @property
    def end_local(self) -> datetime:
        return self.end.astimezone(DISPLAY_TZ)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "TimeCrossRestNV/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def unfold(ics_text: str) -> list[str]:
    """iCal-строки могут быть разбиты переносом + пробелом — склеиваем обратно."""
    lines: list[str] = []
    for raw in ics_text.splitlines():
        if raw.startswith((" ", "\t")) and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def parse_dt(value: str) -> datetime:
    # Google всегда отдаёт UTC с суффиксом Z, но обработаем и локальное время
    if value.endswith("Z"):
        return datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    if "T" in value:
        return datetime.strptime(value, "%Y%m%dT%H%M%S").replace(tzinfo=DISPLAY_TZ)
    return datetime.strptime(value, "%Y%m%d").replace(tzinfo=DISPLAY_TZ)


def parse_events(ics_text: str) -> list[Event]:
    events: list[Event] = []
    current: dict | None = None
    for line in unfold(ics_text):
        if line == "BEGIN:VEVENT":
            current = {}
            continue
        if line == "END:VEVENT":
            if current and "start" in current and "end" in current:
                events.append(
                    Event(
                        summary=current.get("summary", "").strip(),
                        start=current["start"],
                        end=current["end"],
                        transparent=current.get("transp", "OPAQUE") == "TRANSPARENT",
                        uid=current.get("uid", ""),
                    )
                )
            current = None
            continue
        if current is None or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key_main = key.split(";", 1)[0].upper()
        if key_main == "DTSTART":
            current["start"] = parse_dt(value)
        elif key_main == "DTEND":
            current["end"] = parse_dt(value)
        elif key_main == "SUMMARY":
            # Раскодируем экранирование iCal: \, \; \n
            current["summary"] = (
                value.replace("\\,", ",").replace("\\;", ";").replace("\\n", " ")
            )
        elif key_main == "TRANSP":
            current["transp"] = value
        elif key_main == "UID":
            current["uid"] = value
    return events


# --- Classification -----------------------------------------------------------


def overlap_minutes(a_start: datetime, a_end: datetime,
                    b_start: datetime, b_end: datetime) -> int:
    start = max(a_start, b_start)
    end = min(a_end, b_end)
    if end <= start:
        return 0
    return int((end - start).total_seconds() // 60)


def classify_days(natasha: list[Event], vova: list[Event]) -> list[dict]:
    """
    Возвращает список дней (по локальной TZ) с горизонтом HORIZON_DAYS.
    Каждый день: статус, смена Наташи (если есть), события Вовы, окна пересечений.
    """
    today = datetime.now(DISPLAY_TZ).date()
    horizon_end = today + timedelta(days=HORIZON_DAYS)

    # Индексируем смены Наташи по дате начала смены (локально)
    natasha_by_date: dict = {}
    for ev in natasha:
        d = ev.start_local.date()
        if today <= d <= horizon_end:
            natasha_by_date.setdefault(d, []).append(ev)

    # Индексируем события Вовы по дате начала
    vova_by_date: dict = {}
    for ev in vova:
        d = ev.start_local.date()
        if today <= d <= horizon_end:
            vova_by_date.setdefault(d, []).append(ev)

    days_out = []
    cur = today
    while cur <= horizon_end:
        n_shifts = natasha_by_date.get(cur, [])
        v_events = vova_by_date.get(cur, [])

        overlaps = []
        status = "green" if (n_shifts or v_events) else "free"

        for shift in n_shifts:
            for v_ev in v_events:
                m = overlap_minutes(
                    shift.start_local, shift.end_local,
                    v_ev.start_local, v_ev.end_local,
                )
                if m > 0:
                    ov_start = max(shift.start_local, v_ev.start_local)
                    ov_end = min(shift.end_local, v_ev.end_local)
                    # Если пересечение заканчивается после KID_BEDTIME_HOUR — это hard
                    is_hard = ov_end.hour >= KID_BEDTIME_HOUR or ov_end.hour < 6
                    overlaps.append({
                        "start": ov_start.strftime("%H:%M"),
                        "end": ov_end.strftime("%H:%M"),
                        "minutes": m,
                        "vova_event": v_ev.summary,
                        "vova_transparent": v_ev.transparent,
                        "hard": is_hard,
                    })

        if n_shifts and overlaps:
            status = "red" if any(o["hard"] for o in overlaps) else "yellow"
        elif n_shifts and not overlaps:
            status = "green"  # Наташа работает, Вова свободен → Вова с дочкой
        elif v_events and not n_shifts:
            status = "free"   # Вова работает, Наташа свободна — нет проблемы

        days_out.append({
            "date": cur.isoformat(),
            "weekday": cur.weekday(),  # 0 = Mon
            "status": status,
            "natasha": [
                {
                    "start": s.start_local.strftime("%H:%M"),
                    "end": s.end_local.strftime("%H:%M") + (
                        " (+1)" if s.end_local.date() != s.start_local.date() else ""
                    ),
                    "summary": s.summary,
                }
                for s in sorted(n_shifts, key=lambda e: e.start_local)
            ],
            "vova": [
                {
                    "start": e.start_local.strftime("%H:%M"),
                    "end": e.end_local.strftime("%H:%M"),
                    "summary": e.summary,
                    "transparent": e.transparent,
                }
                for e in sorted(v_events, key=lambda e: e.start_local)
            ],
            "overlaps": overlaps,
        })
        cur += timedelta(days=1)

    return days_out


# --- Encryption ---------------------------------------------------------------


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def encrypt_payload(payload: dict, password: str) -> dict:
    """AES-GCM шифрование, совместимое с Web Crypto API."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print(
            "ERROR: пакет `cryptography` не установлен.\n"
            "Поставь: pip install cryptography",
            file=sys.stderr,
        )
        sys.exit(1)

    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)

    return {
        "v": 1,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": b64(salt),
        "iv": b64(iv),
        "ciphertext": b64(ciphertext),
    }


# --- Main ---------------------------------------------------------------------


def main() -> int:
    password = os.environ.get("SITE_PASSWORD", "1131")
    print(f"Используется пароль длиной {len(password)} символов "
          f"(значение из ENV {'есть' if 'SITE_PASSWORD' in os.environ else 'нет, fallback'})")

    print("Скачиваю календарь Наташи...")
    natasha_ics = fetch(NATASHA_ICS)
    print("Скачиваю календарь Вовы...")
    vova_ics = fetch(VOVA_ICS)

    natasha_events = parse_events(natasha_ics)
    vova_events = parse_events(vova_ics)
    print(f"Распарсено событий: Наташа={len(natasha_events)}, Вова={len(vova_events)}")

    days = classify_days(natasha_events, vova_events)
    counts = {"red": 0, "yellow": 0, "green": 0, "free": 0}
    for d in days:
        counts[d["status"]] += 1
    print(f"Дней по статусам: {counts}")

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "horizon_days": HORIZON_DAYS,
        "kid_bedtime_hour": KID_BEDTIME_HOUR,
        "tz": str(DISPLAY_TZ),
        "days": days,
    }

    OUT_DIR.mkdir(exist_ok=True)
    enc = encrypt_payload(payload, password)
    (OUT_DIR / "data.enc.json").write_text(
        json.dumps(enc, separators=(",", ":")), encoding="utf-8"
    )
    print(f"Зашифрованный блок записан: {OUT_DIR / 'data.enc.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
