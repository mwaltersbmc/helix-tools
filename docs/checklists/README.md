# Helix checklists

Operator checklists exported from [Helix xWiki](https://wiki.helixops.ai/).

## Adding or updating a checklist

The internal wiki requires **Okta sign-in**. Automated fetch from CI or unauthenticated tools is not possible.

### Export from xWiki (while logged in)

1. Open the page in your browser.
2. Use **More actions** (⋮) → **Export** → **HTML** (or **Markdown** if offered).
3. Save the export file, or use the direct export URL (same browser session):

   ```text
   https://wiki.helixops.ai/xwiki/bin/export/Personal-Spaces/mwalters/Helix-Content/Helix-Authentication-Troubleshooting-Checklist?format=html
   ```

   For Markdown export (when enabled on the wiki):

   ```text
   https://wiki.helixops.ai/xwiki/bin/export/Personal-Spaces/mwalters/Helix-Content/Helix-Authentication-Troubleshooting-Checklist?format=markdown
   ```

4. From the repo root, convert HTML to Markdown:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\import-xwiki-page.ps1 `
     -InputHtml docs\checklists\_source\Authentication.html `
     -OutputMd docs\checklists\Authentication.md
   ```

   If xWiki exported Markdown directly, copy/rename that file to `Authentication.md` and skip the script.

5. Review the Markdown (headings, tables, links) before committing.

### Files

| File | Role |
|------|------|
| `Authentication.md` | Helix authentication troubleshooting checklist |
| `images/` | Screenshots from the xWiki export |
| `_source/` | Optional raw xWiki HTML exports (not required in git) |
