#!/bin/sh
set -e

BP="${BASE_PATH:-}"
STATIC="${STATIC_DIR:-/srv/static}"
SENTINEL="/__HAPPYVIEW_BP__"
SENTINEL_DIR="__HAPPYVIEW_BP__"

# Only run replacement if the sentinel directory exists (first boot)
if [ -d "${STATIC}/${SENTINEL_DIR}" ]; then
    if [ -n "$BP" ]; then
        # Validate: must start with /
        case "$BP" in
            /*) ;;
            *) echo "ERROR: BASE_PATH must start with '/' (got: $BP)" >&2; exit 1 ;;
        esac
        # Strip trailing slash
        BP="${BP%/}"
        BP_DIR="${BP#/}"

        # Rename sentinel directory to match base path
        mv "${STATIC}/${SENTINEL_DIR}" "${STATIC}/${BP_DIR}"

        # Replace sentinel string in static files
        find "${STATIC}" -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' \) \
            -exec sed -i "s|${SENTINEL}|${BP}|g" {} +
    else
        # No base path: move files from sentinel directory to static root
        cp -a "${STATIC}/${SENTINEL_DIR}/." "${STATIC}/"
        rm -rf "${STATIC}/${SENTINEL_DIR}"

        # Remove sentinel string from static files
        find "${STATIC}" -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' \) \
            -exec sed -i "s|${SENTINEL}||g" {} +
    fi
fi

exec happyview "$@"
