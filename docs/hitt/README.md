# HITT web use-case help

Interactive use-case reference: open [`index.html`](index.html) locally (with sibling assets) or publish via GitHub Pages from the repo `/docs` folder (path is usually `/helix-tools/hitt/` on project Pages).

## When you change use cases

1. **Edit the canonical file:** [`use-cases.json`](use-cases.json)  
   - **`topics[]`:** each topic has `id`, `title`, `order` (section order on the page; lower first).  
   - **`useCases[]`:** each row has `id`, `topicId` (must match a topic `id`), `order` (within that section), `title`, optional `commands[]`, `notes[]`, optional `seeAlso` (URL).

2. **Regenerate the offline bundle:** run [`update-bundled-data.ps1`](update-bundled-data.ps1) so [`use-cases-data.js`](use-cases-data.js) stays in sync (required for **File → Open** / `file://`; the app loads `window.HITT_USE_CASES` before falling back to `fetch`).

   From repo root (Windows PowerShell):

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File docs\hitt\update-bundled-data.ps1
   ```

   Or from this directory:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\update-bundled-data.ps1
   ```

3. **Commit both** `use-cases.json` and `use-cases-data.js` in the same change whenever JSON content changes.

4. **Smoke-check:** open `index.html` in a browser (local folder) and confirm sections and copy buttons.

## Keep prose aligned with the product

User-facing copy in `use-cases.json` and `hitt/README*.md` should follow **`.cursor/rules/hitt-user-facing-docs.mdc`**: plain language for operators, no internal function names, no implicit “kubectl/cluster access” prerequisites, and no Kubernetes object names unless the user must know them for that command (for example a secret name passed to **get secret**).

When you add or change CLI behavior, update the matching narrative docs so the site does not drift:

| Change touches | Also review |
|----------------|-------------|
| General modes / flags | [`../../hitt/README.md`](../../hitt/README.md) |
| `-f` / fix flows | [`../../hitt/README-fix-mode.md`](../../hitt/README-fix-mode.md) |
| `-u` / utility | [`../../hitt/README-utility-mode.md`](../../hitt/README-utility-mode.md) |
| Built-in help text | `hitt.sh` (`showFixHelp`, `showUtilHelp`, etc.) |

## Files in this folder

| File | Role |
|------|------|
| `use-cases.json` | Source data (edit here). |
| `use-cases-data.js` | Generated: `window.HITT_USE_CASES = …` — do not hand-edit. |
| `update-bundled-data.ps1` | JSON → JS sync script. |
| `index.html`, `styles.css`, `app.js` | Page shell and behavior. |

Minimum set for offline **File → Open:** `index.html`, `styles.css`, `app.js`, `use-cases-data.js` (same directory).
