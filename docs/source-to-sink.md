# Source-to-sink: Incident Description і IncidentComment.Text (baseline 2-A)

## Потік 1 — Incident Description (основний flow)

| Крок | Точне місце | Значення / доказ | Довіра |
|---|---|---|---|
| Source | `browser-lab.html`, `<textarea name="description">` у `form#edit` | текст користувача | контрольоване користувачем |
| Request | `browser-lab.js`, submit handler, `JSON.stringify({ … description … })` → `POST /api/incidents` | поле `description` у Payload (Скрін 6) | контрольоване користувачем |
| Server | `IncidentCommands.CreateAsync` (ЛР 2), валідація довжини/обов'язковості | `request.Description.Trim()`; HTML-символи не змінюються | валідація не робить значення довіреним |
| Storage | `Incident.Description` у PostgreSQL | те саме значення | збережене значення користувача |
| Response | `GET /api/incidents/{id}`, JSON `description` | видно в Network (Скрін 6) | недовірене для DOM |
| Client transform | `browser-lab.js`, `load()`: `current = await response.json()` | `current.description` | недовірене |
| Sink | `browser-lab.js`, `load()`: `document.querySelector("#description").innerHTML = current.description` | HTML-context | **небезпечний** |

## Потік 2 — IncidentComment.Text (друге поле, добрий рівень)

| Крок | Точне місце | Значення / доказ | Довіра |
|---|---|---|---|
| Source | seed `StoredProbeText` у `DbSeeder.SeedAsync` (у продукті — автор коментаря) | той самий marker, що і в полі опису | контрольоване користувачем |
| Storage | `IncidentComment.Text` у PostgreSQL | збережене значення | збережене значення користувача |
| Response | `GET /api/incidents/{id}`, JSON `comments[].text` | видно в Network (Скрін 10) | недовірене для DOM |
| Client transform | `browser-lab.js`, цикл `for (const comment of current.comments ?? [])` | `comment.text` | недовірене |
| Sink | `browser-lab.js`: `paragraph.innerHTML = comment.text` | HTML-context | **небезпечний** |

## Гіпотеза

Значення з `<textarea name="description">` зберігається в `Incident.Description`, повертається в `description` і передається в `innerHTML` елемента `#description` як HTML-context. За умови контролю над полем браузер інтерпретує дані як розмітку, а не як текст. Аналогічно для `IncidentComment.Text` через `paragraph.innerHTML`.

## Finding

| Поле | Зміст |
|---|---|
| **Актив** | сеанс користувача (cookie Identity), браузерний контекст |
| **Передумови** | акаунт (Alice) + контроль над полем опису інциденту або коментаря |
| **Першопричина** | недовірене значення потрапляє в HTML-sink (`innerHTML`) замість text node |
| **Вплив (marker)** | `#lab05-marker-target` отримує `data-lab05-marker="executed"`; даних не витікає, зовнішніх запитів немає |
| **Виправлення** | safe DOM: `textContent` / `createTextNode` замість `innerHTML` |
| **Retest** | marker не виконується (Скріни 14-17), hash опису не змінюється (Скрін 13) |
| **Залишковий ризик** | CSP у Development; CSRF до ЛР 6; `style-src` не звужено окремо |
