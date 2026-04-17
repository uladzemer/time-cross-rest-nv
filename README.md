# TimeCrossRestNV

Семейный дашборд: считает пересечения смен Наташи и рабочих событий Вовы на 60 дней вперёд, чтобы планировать уход за дочкой.

Каждый день классифицируется:
- 🟥 **жёсткий** — у обоих работа после 20:00, нужно вызывать тёщу или кто-то отменяет работу
- 🟨 **мягкий** — пересечение есть, но Вова освобождается до 20:00 — можно забрать/привезти дочку
- 🟩 **зелёный** — Наташа на смене, Вова свободен → дома с дочкой
- ⚪ **свободный** — у обоих нет работы

## Архитектура

- `generate.py` — Python-скрипт без внешних зависимостей кроме `cryptography`. Качает оба `.ics`, парсит, классифицирует, шифрует данные паролем (PBKDF2-HMAC-SHA256, 200k итераций → AES-GCM)
- `docs/` — статический сайт для GitHub Pages. Принимает пароль, расшифровывает `data.enc.json` через Web Crypto API, рисует дашборд
- `.github/workflows/update.yml` — раз в час качает свежие данные, шифрует, деплоит на Pages

Зашифрованный `docs/data.enc.json` создаётся скриптом и НЕ хранится в git (см. `.gitignore`).

## Локальный запуск

```bash
pip install cryptography tzdata
python generate.py
cd docs && python -m http.server 8765
# Открыть http://localhost:8765/ , пароль "1131"
```

Пароль читается из ENV `SITE_PASSWORD`, по умолчанию `1131`.

## Развёртывание на GitHub Pages

1. Создай **публичный** репозиторий на github.com (например `time-cross-rest-nv`). Не добавляй README/`.gitignore` через UI — они уже есть локально
2. В этой папке выполни:
   ```bash
   git init
   git branch -M main
   git remote add origin https://github.com/<TWOJ-USERNAME>/time-cross-rest-nv.git
   git add .
   git commit -m "Initial commit"
   git push -u origin main
   ```
3. В репозитории на github.com:
   - **Settings → Pages → Build and deployment → Source = GitHub Actions**
   - **Settings → Secrets and variables → Actions → New repository secret**
     - Name: `SITE_PASSWORD`
     - Value: `1131` (или любой другой)
4. Зайди в **Actions → "Update and deploy dashboard" → Run workflow** для первого деплоя
5. После завершения workflow ссылка появится в `Actions → последний запуск → deploy → Page URL`. Обычно это `https://<username>.github.io/time-cross-rest-nv/`

Дальше дашборд будет обновляться сам каждый час.

## Безопасность пароля

Это **обфускация, а не криптозащита**. Пароль `1131` короткий (10 000 комбинаций), его можно сбрутфорсить за минуты. PBKDF2 на 200k итераций замедляет перебор, но не делает его невозможным. Защита спасает от случайного человека, нашедшего ссылку, не от целенаправленной атаки.

Если данные действительно чувствительны — нужен длинный пароль (10+ символов) или приватный репозиторий с GitHub Pro.

## Что показывается жене

Одна ссылка вида `https://<username>.github.io/time-cross-rest-nv/`. На входе — поле для пароля. После ввода — список ближайших 60 дней с цветовой индикацией и деталями: смены Наташи, события Вовы, окна пересечений с длительностью.
