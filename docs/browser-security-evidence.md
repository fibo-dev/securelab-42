# Докази безпеки браузера (DEL-01)

Рівень: **добрий («Добре»)**.

## Стенд

- ОС: Ubuntu 24.04, Firefox
- API: `http://localhost:5080`, probes: `http://localhost:4173` (allow), `http://localhost:4174` (deny)
- Release scaffold: `lab-05-start-v1`, base_commit: `48534bf` (v0.4.0)
- Vulnerable commit: `dfe2eb0`, Fixed commit: `<hash з Кроку 14>`, Tag: `v0.5.0`
- Cookie `.AspNetCore.Identity.Application`: HttpOnly=true, SameSite=Lax, Secure=false (Dev/HTTP)

## XSS (REG-XSS-01)

- **PX (Guid створеного інциденту):** `3cd40ea5-26f5-4981-ad98-8e23a1e50803`
- **Marker (з `resources/lab05-marker.txt`):**

  ```html
  <img src=x onerror="document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')">
  ```

- **Seed-коментар:** `30000000-0000-0000-0000-0000000005a1` → інцидент `20000000-0000-0000-0000-000000000001`
- **Карта source→sink:** див. `docs/source-to-sink.md`

| Що | До fix | Після fix |
|---|---|---|
| Hash опису (len sha256[:16]) | `113 7a9f72c6648a0f90` | `113 7a9f72c6648a0f90` |
| Description DOM | `<img onerror>` + `'executed'` | text node + `null` |
| Comment DOM | `<img onerror>` + `'executed'` | text node + `null` |
| Morgan (Analyst) | `GET: 200` + `'executed'` | `GET: 200` + `null` |
| Bob (Reporter, не власник) | `GET: 404` + `null` | `GET: 404` + `null` |
| N2 (`<b>жирний</b>`) | напівжирне | символи як текст |

**Fix (3 рядки):**

```diff
+function writePlain(target, value) {
+  target.replaceChildren(document.createTextNode(value ?? ""));
+  return target;
+}
-document.querySelector("#description").innerHTML = current.description;
+writePlain(document.querySelector("#description"), current.description);
-paragraph.innerHTML = comment.text;
+writePlain(paragraph, comment.text);
```

**Finding:** недовірений текст з `<textarea name="description">` (і `IncidentComment.Text`) потрапляє в HTML-sink `innerHTML`. Виправлено заміною на `textContent`/`createTextNode`. Залишковий ризик: CSRF (ЛР 6), CSP тільки в Development, `style-src` не звужено.

## CORS (REG-CORS-01)

| Origin / запит | До policy | Fixed |
|---|---|---|
| 5080 same-origin | JS читає | JS читає |
| 4173 simple GET | 200, JS не читає | 200, JS читає, `ACAO: http://localhost:4173` |
| 4173 preflight (X-Lab-Cors-Probe) | OPTIONS 405 | OPTIONS 204 + `ACA-Methods/Headers`, GET 200 |
| 4174 simple GET | 200, JS не читає | 200, JS не читає (без ACAO) |
| 4174 preflight | OPTIONS 405 | OPTIONS 204 без `ACA-*`, GET не надіслано |
| 4174 з cookie (`credentials: include`) | — | запит із cookie пішов, response заблоковано → **CSRF не закритий** |

**HTTP-докази:**

```bash
curl -sS -D - -o /dev/null -H "Origin: http://localhost:4173" http://localhost:5080/health
# → 200 OK, ACAO: http://localhost:4173, ACA-Credentials: true

curl -sS -D - -o /dev/null -H "Origin: http://localhost:4174" http://localhost:5080/health
# → 200 OK, без Access-Control-*
```

**Policy:** лише Development, один exact origin `http://localhost:4173`, `GET`, header `X-Lab-Cors-Probe`, `.AllowCredentials()`.

**Порядок middleware:** `UseRouting → UseCors → UseAuthentication → UseAuthorization → UseRateLimiter` (перевірено: rate-limit ЛР 3 працює).

## CSP і headers

- **CSP:** `default-src 'self'; frame-ancestors 'none'` (у `Program.cs` middleware, `/scalar` виключено в Dev)
- **Enforcement:** document `browser-lab.html` віддається з цим CSP; `new Image().src="http://localhost:4173/x.png"` → заблоковано (Скрін 27)
- **X-Content-Type-Options:** `nosniff` — захист від MIME sniffing
- **Referrer-Policy:** `no-referrer` — витік URL

## Review (для DEL-03)

- **XSS:** недовірений текст в HTML-sink; fix лише в sink.
- **CORS:** дозволяє браузеру прочитати cross-origin response; не автентифікує і не обмежує `curl`.
- **CSRF:** cookie надсилається автоматично; `AllowCredentials` не захищає від CSRF (Скрін 25); anti-CSRF — ЛР 6.
- **Authorization:** сервер перевіряє principal+action+resource (ЛР 4); Bob отримав 404 на чужий інцидент.
