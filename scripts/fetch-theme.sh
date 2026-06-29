#!/usr/bin/env bash
# Fetch a docs-theme release (or an unreleased commit) and install it into
# docs/.theme.
# Reads docs/theme.toml for repo, template, and exactly one source selector:
# version (released docs-theme) or rev (pre-release commit SHA for testing).
# Skips the download when the installed metadata already matches.
#
# version and rev are mutually exclusive — docs/theme.toml must activate
# exactly one. Use version for releases; comment out version and set rev only
# when testing an unreleased commit (see the commented example in theme.toml).
#
# When rev is active, the script downloads that commit SHA via gh api.
# When version is active, the script downloads the release identified by
# version.
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

# Active source selectors: uncommented version= or rev= lines only.
VERSION_ACTIVE=$(
  grep -E '^[[:space:]]*version[[:space:]]*=' "$CONFIG" \
    | grep -Ev '^[[:space:]]*#' || true
)
REV_ACTIVE=$(
  grep -E '^[[:space:]]*rev[[:space:]]*=' "$CONFIG" \
    | grep -Ev '^[[:space:]]*#' || true
)

VERSION_COUNT=0
REV_COUNT=0
[[ -n "$VERSION_ACTIVE" ]] && VERSION_COUNT=1
[[ -n "$REV_ACTIVE" ]] && REV_COUNT=1
SELECTOR_COUNT=$((VERSION_COUNT + REV_COUNT))

if [[ "$SELECTOR_COUNT" -ne 1 ]]; then
  cat >&2 <<EOF
Error: docs/theme.toml must have exactly one active source selector: either 'version' (for released docs-theme) or 'rev' (for pre-release testing). Found $SELECTOR_COUNT active selectors.

Expected default config:

  repo = "aicers/docs-theme"
  template = "manual"
  version = "0.1.0"
  # rev = "COMMIT_SHA"  # use instead of version for pre-release testing
EOF
  exit 1
fi

REPO="$(read_toml repo)"
TEMPLATE="$(read_toml template)"

if [[ -z "$REPO" || -z "$TEMPLATE" ]]; then
  echo "Error: docs/theme.toml must define repo and template" >&2
  exit 1
fi

if [[ -n "$REV_ACTIVE" ]]; then
  REV="$(
    echo "$REV_ACTIVE" \
      | sed -E 's/^[[:space:]]*rev[[:space:]]*=[[:space:]]*"?([^"]+)"?.*/\1/' \
      | head -1
  )"
  REV="${REV//[[:space:]]/}"
  if [[ -z "$REV" ]]; then
    echo "Error: rev must be a non-empty string when active in docs/theme.toml" >&2
    exit 1
  fi
  VERSION=""
else
  VERSION="$(
    echo "$VERSION_ACTIVE" \
      | sed -E 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"?([^"]+)"?.*/\1/' \
      | head -1
  )"
  REV=""
  if [[ -z "$VERSION" ]]; then
    echo "Error: version must be a non-empty string when active in docs/theme.toml" >&2
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
