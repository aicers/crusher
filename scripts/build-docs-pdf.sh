#!/usr/bin/env bash
set -euo pipefail

python_bin="python3"
mkdocs_bin="mkdocs"

if [[ -x ".venv/bin/python" ]]; then
  python_bin=".venv/bin/python"
fi

if [[ -x ".venv/bin/mkdocs" ]]; then
  mkdocs_bin=".venv/bin/mkdocs"
fi

if [[ ! -d "docs/.theme" ]]; then
  echo "Error: docs/.theme not found. Run ./scripts/fetch-theme.sh first." >&2
  exit 1
fi

trap 'rm -f mkdocs.tmp.yml; if [[ "${CRUSHER_PDF_DEBUG:-0}" != "1" ]]; then rm -rf .pdf-tmp; fi' EXIT

"$python_bin" - <<'PY'
import copy
import os
import sys
from datetime import datetime
import shutil
import yaml

with open("mkdocs.yml", "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)

data = copy.deepcopy(data)
root = os.getcwd()

tmp_pdf_dir = os.path.join(root, ".pdf-tmp")
if os.path.exists(tmp_pdf_dir):
    shutil.rmtree(tmp_pdf_dir)
theme_dir = os.path.join(root, "docs", ".theme")
shutil.copytree(os.path.join(theme_dir, "pdf"), tmp_pdf_dir)

fonts_dir = os.path.join(theme_dir, "fonts")
shutil.copytree(fonts_dir, os.path.join(tmp_pdf_dir, "fonts"))

styles_path = os.path.join(tmp_pdf_dir, "styles.scss")
fonts_base = f'file://{os.path.join(tmp_pdf_dir, "fonts")}/'

with open(styles_path, "r", encoding="utf-8") as f:
    styles = f.read()

for prefix in ('../fonts/', 'pdf/fonts/', '/pdf/fonts/', 'fonts/'):
    styles = styles.replace(f'url("{prefix}', f'url("{fonts_base}')

with open(styles_path, "w", encoding="utf-8") as f:
    f.write(styles)

data["strict"] = False
data["site_dir"] = "site-pdf"

theme = data.get("theme")
if isinstance(theme, dict):
    theme["font"] = False

now = datetime.now()

pdf_plugin = {
    "with-pdf": {
        "enabled_if_env": "CRUSHER_PDF_EXPORT",
        "output_path": os.path.join(root, "site", "pdf", "crusher-manual.pdf"),
        "custom_template_path": tmp_pdf_dir,
        "author": f"Crusher\n{now.strftime('%B %-d, %Y')}",
        "copyright": "\u00a9 2026 ClumL Inc.",
        "cover_logo": "docs/.theme/brand.svg",
        "cover_title": "Crusher",
        "cover_subtitle": "User Manual",
        "toc_title": "Table of Contents",
    }
}

data.setdefault("plugins", []).append(pdf_plugin)

with open("mkdocs.tmp.yml", "w", encoding="utf-8") as f:
    yaml.safe_dump(data, f, sort_keys=False)
PY

CRUSHER_PDF_EXPORT=1 "$mkdocs_bin" build -f mkdocs.tmp.yml
