#!/usr/bin/env bash
# Fetch a docs-theme release (or an unreleased commit) and install it into
# docs/.theme.
# Reads docs/theme.toml for repo, template, version, and optional rev.
# Skips the download when the installed metadata already matches.
#
# When rev is set in docs/theme.toml, the script downloads that commit SHA via
# gh api for local/pre-release testing. Keep the rev comment on its own line
# in theme.toml (see the example there).
# When rev is unset, the script downloads the release identified by version.
#
# Requirements: gh (GitHub CLI), tar
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CONFIG="$ROOT_DIR/docs/theme.toml"
DEST="$ROOT_DIR/docs/.theme"

if [[ ! -f "$CONFIG" ]]; then
  echo "Error: $CONFIG not found" >&2
  exit 1
fi

read_toml() {
  grep "^${1} " "$CONFIG" | sed 's/.*= *"\(.*\)"/\1/'
}

read_toml_optional() {
  grep "^${1} " "$CONFIG" | sed 's/.*= *"\(.*\)"/\1/' || true
}

REPO="$(read_toml repo)"
TEMPLATE="$(read_toml template)"
VERSION="$(read_toml version)"
REV="$(read_toml_optional rev)"

if [[ -z "$REPO" || -z "$TEMPLATE" || -z "$VERSION" ]]; then
  echo "Error: docs/theme.toml must define repo, template, and version" >&2
  exit 1
fi

if [[ -n "$REV" ]]; then
  REV="${REV//[[:space:]]/}"
  if [[ -z "$REV" ]]; then
    echo "Error: rev must be a non-empty string when set in docs/theme.toml" >&2
    exit 1
  fi
fi

# Skip if installed metadata already matches.
META="$DEST/.meta"
if [[ -f "$META" ]]; then
  installed_repo="$(grep "^repo " "$META" | sed 's/.*= *"\(.*\)"/\1/' || true)"
  installed_version="$(grep "^version " "$META" | sed 's/.*= *"\(.*\)"/\1/' || true)"
  installed_template="$(grep "^template " "$META" | sed 's/.*= *"\(.*\)"/\1/' || true)"
  installed_rev="$(grep "^rev " "$META" | sed 's/.*= *"\(.*\)"/\1/' || true)"
  if [[ -n "$REV" ]]; then
    if [[ "$installed_repo" == "$REPO" && "$installed_rev" == "$REV" && "$installed_template" == "$TEMPLATE" ]]; then
      echo "docs-theme rev $REV ($TEMPLATE) already installed — skipping"
      exit 0
    fi
  elif [[ "$installed_repo" == "$REPO" && "$installed_version" == "$VERSION" && "$installed_template" == "$TEMPLATE" && -z "$installed_rev" ]]; then
    echo "docs-theme $VERSION ($TEMPLATE) already installed — skipping"
    exit 0
  fi
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

if [[ -n "$REV" ]]; then
  echo "Fetching docs-theme rev $REV (template: $TEMPLATE)..."
  ARCHIVE="$WORK_DIR/theme.tar.gz"
  gh api "/repos/${REPO}/tarball/${REV}" > "$ARCHIVE"
else
  echo "Fetching docs-theme $VERSION (template: $TEMPLATE)..."
  gh release download "$VERSION" \
    --repo "$REPO" \
    --archive tar.gz \
    --dir "$WORK_DIR"
  ARCHIVE="$(ls "$WORK_DIR"/*.tar.gz)"
fi

tar -xzf "$ARCHIVE" -C "$WORK_DIR"

EXTRACTED="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)"
if [[ -z "$EXTRACTED" || ! -d "$EXTRACTED" ]]; then
  if [[ -n "$REV" ]]; then
    echo "Error: could not find extracted theme directory for rev $REV" >&2
  else
    echo "Error: could not find extracted theme directory for release $VERSION" >&2
  fi
  exit 1
fi

TEMPLATE_DIR="$EXTRACTED/templates/$TEMPLATE"
if [[ ! -d "$TEMPLATE_DIR" ]]; then
  if [[ -n "$REV" ]]; then
    echo "Error: template '$TEMPLATE' not found at rev $REV" >&2
  else
    echo "Error: template '$TEMPLATE' not found in release $VERSION" >&2
  fi
  exit 1
fi

SHARED_DIR="$EXTRACTED/shared"

rm -rf "$DEST"
mkdir -p "$DEST"

# Copy template-specific assets.
cp -r "$TEMPLATE_DIR"/styles "$DEST"/
if [[ -d "$TEMPLATE_DIR/pdf" ]]; then
  cp -r "$TEMPLATE_DIR"/pdf "$DEST"/
fi

# Copy shared assets.
if [[ -d "$SHARED_DIR/fonts" ]]; then
  mkdir -p "$DEST/fonts"
  cp -r "$SHARED_DIR"/fonts/* "$DEST"/fonts/
fi

if [[ -f "$SHARED_DIR/brand.svg" ]]; then
  cp "$SHARED_DIR/brand.svg" "$DEST"/
fi

# Write installed metadata so subsequent runs can skip.
if [[ -n "$REV" ]]; then
  cat > "$META" <<EOF
repo = "$REPO"
template = "$TEMPLATE"
rev = "$REV"
EOF
  echo "Installed docs-theme rev $REV ($TEMPLATE) into $DEST"
else
  cat > "$META" <<EOF
repo = "$REPO"
version = "$VERSION"
template = "$TEMPLATE"
EOF
  echo "Installed docs-theme $VERSION ($TEMPLATE) into $DEST"
fi
