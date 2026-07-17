#!/bin/bash

set -euo pipefail

CALLER_DIR="$PWD"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ "$EUID" -eq 0 ]]; then
    echo "[!] Do not run the nonce setter with sudo or as root." >&2
    exit 1
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
NONCECTL="$SCRIPT_DIR/tools/noncectl.py"
NONCE_CACHE="$SCRIPT_DIR/boot/iPhone11,8/nonce"
NONCE_RECORDS="$SCRIPT_DIR/nonce"

NONCE_IBSS_VERSION="14.4.2"
NONCE_IBSS_BUILD="18D70"
NONCE_IBSS_NAME="iBSS.n841.RELEASE.im4p"
NONCE_IBSS_KEY="8c8e5c5d2acad2d465ed27ac88ce62032bee442c29a33de4bd207a4d3cd22485fbd504507a6dafc7cade551644761fb8"
NONCE_IBSS_URL="https://updates.cdn-apple.com/2021WinterFCS/fullrestores/071-22451/5C8BBEE0-8471-4801-8D85-54D33DEDA50D/iPhone11,8,iPhone12,1_14.4.2_18D70_Restore.ipsw"
NONCE_IBSS_PATCHED="$NONCE_CACHE/iBSS.n841.${NONCE_IBSS_VERSION}-${NONCE_IBSS_BUILD}.nonce.patched"
NONCE_IBSS_RAW_SHA256="c9103d9e5c8a0cd94ca6e7c25bdb2f2b06d93f0ef3cb5b204284607937b65e98"
NONCE_IBSS_PATCHED_SHA256="5dda02a919505728f29b0aba2da57e9efa2066bad50f2dc6e738d72b8b6e1630"

usage() {
    cat <<'EOF'
Usage:
  ./xr-nonce-setter.sh set GENERATOR_OR_SHSH [--ibss RAW_PATCHED_IBSS] [--boot-normal]

The set command requires an iPhone XR already in usbliter8 pwned DFU mode.
It prepares and boots the patched iBSS, sets and verifies the generator,
reboots to recovery, and records the resulting APNonce pair.
EOF
}

resolve_caller_path() {
    local value="$1"
    if [[ "$value" != /* && -f "$CALLER_DIR/$value" ]]; then
        printf '%s/%s\n' "$CALLER_DIR" "$value"
    else
        printf '%s\n' "$value"
    fi
}

find_tool() {
    local bundled="$1"
    local system_name="$2"
    if [[ -x "$bundled" ]]; then
        printf '%s\n' "$bundled"
    elif command -v "$system_name" >/dev/null 2>&1; then
        command -v "$system_name"
    else
        return 1
    fi
}

download_tool() {
    local destination="$1"
    local url="$2"
    local temporary="${destination}.download"

    mkdir -p "$(dirname "$destination")"
    rm -f "$temporary"
    curl -fL --retry 3 -o "$temporary" "$url"
    chmod +x "$temporary"
    mv "$temporary" "$destination"
}

ensure_nonce_tools() {
    local platform
    local img4_url
    local pzb_url
    local irecovery_url
    local patcher_url

    platform="$(uname -s)"
    case "$platform" in
        Darwin)
            img4_url="https://github.com/LukeZGD/Semaphorin/raw/refs/heads/main/Darwin/img4"
            pzb_url="https://github.com/LukeZGD/Semaphorin/raw/refs/heads/main/Darwin/pzb"
            irecovery_url="https://github.com/LukeZGD/Semaphorin/raw/refs/heads/main/Darwin/irecovery"
            patcher_url="https://github.com/Orangera1n/spironolactone/raw/refs/heads/main/Darwin/iBoot64Patcher_cryptic"
            ;;
        Linux)
            if [[ "$(uname -m)" != "x86_64" ]]; then
                echo "[!] Automatic nonce tool download currently supports x86_64 Linux only." >&2
                echo "[!] Put compatible img4, pzb, irecovery, and iBoot64Patcher2 binaries in bin/." >&2
                return 1
            fi
            img4_url="https://github.com/LukeZGD/Semaphorin/raw/refs/heads/main/Linux/img4"
            pzb_url="https://github.com/LukeZGD/Semaphorin/raw/refs/heads/main/Linux/pzb"
            irecovery_url="https://github.com/LukeZGD/Semaphorin/raw/refs/heads/main/Linux/irecovery"
            patcher_url="https://github.com/appleiPodTouch4/spironolactone/raw/refs/heads/main/Linux/x86_64/iBoot64patcher_cryptic"
            ;;
        *)
            echo "[!] Unsupported host platform: $platform" >&2
            return 1
            ;;
    esac

    [[ -x bin/img4 ]] || download_tool bin/img4 "$img4_url"
    [[ -x bin/pzb ]] || download_tool bin/pzb "$pzb_url"
    [[ -x bin/irecovery ]] || download_tool bin/irecovery "$irecovery_url"
    [[ -x bin/iBoot64Patcher2 ]] || download_tool bin/iBoot64Patcher2 "$patcher_url"
}

ensure_pyusb() {
    if ! "$PYTHON_BIN" -c 'import usb.core' >/dev/null 2>&1; then
        echo "[!] pyusb is required." >&2
        echo "[!] Install it with: $PYTHON_BIN -m pip install pyusb" >&2
        return 1
    fi
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "[!] sha256sum or shasum is required to verify the nonce iBSS." >&2
        return 1
    fi
}

verify_hash() {
    local path="$1"
    local expected="$2"
    local actual
    actual="$(sha256_file "$path")"
    if [[ "$actual" != "$expected" ]]; then
        echo "[!] SHA-256 mismatch for $path" >&2
        echo "[!] Expected: $expected" >&2
        echo "[!] Actual:   $actual" >&2
        return 1
    fi
}

prepare_nonce_ibss() {
    if [[ -s "$NONCE_IBSS_PATCHED" ]]; then
        if verify_hash "$NONCE_IBSS_PATCHED" "$NONCE_IBSS_PATCHED_SHA256"; then
            printf '%s\n' "$NONCE_IBSS_PATCHED"
            return
        fi
        echo "[!] Rebuilding the cached nonce iBSS." >&2
        rm -f "$NONCE_IBSS_PATCHED"
    fi

    ensure_nonce_tools

    local workdir="$SCRIPT_DIR/work/nonce"
    local encrypted="$workdir/$NONCE_IBSS_NAME"
    local raw="$workdir/iBSS.n841.${NONCE_IBSS_VERSION}.raw"
    local temporary_patch="$workdir/iBSS.n841.${NONCE_IBSS_VERSION}.nonce.patched"

    mkdir -p "$workdir" "$NONCE_CACHE"
    rm -f "$encrypted" "$raw" "$temporary_patch"

    (
        cd "$workdir"
        "$SCRIPT_DIR/bin/pzb" -g "Firmware/dfu/$NONCE_IBSS_NAME" "$NONCE_IBSS_URL"
    )

    if [[ ! -s "$encrypted" ]]; then
        echo "[!] Failed to fetch $NONCE_IBSS_NAME from Apple's IPSW." >&2
        return 1
    fi

    "$SCRIPT_DIR/bin/img4" -i "$encrypted" -o "$raw" -k "$NONCE_IBSS_KEY"
    verify_hash "$raw" "$NONCE_IBSS_RAW_SHA256"
    "$SCRIPT_DIR/bin/iBoot64Patcher2" "$raw" "$temporary_patch" -n

    if [[ ! -s "$temporary_patch" ]]; then
        echo "[!] iBoot64Patcher2 did not produce the nonce iBSS." >&2
        return 1
    fi

    verify_hash "$temporary_patch" "$NONCE_IBSS_PATCHED_SHA256"
    mv "$temporary_patch" "$NONCE_IBSS_PATCHED"
    rm -f "$encrypted" "$raw"
    printf '%s\n' "$NONCE_IBSS_PATCHED"
}

irecovery_query() {
    local irecovery
    irecovery="$(find_tool "$SCRIPT_DIR/bin/irecovery" irecovery)" || {
        echo "[!] irecovery is missing; run the set command to prepare the required tools." >&2
        return 1
    }
    "$irecovery" -q 2>/dev/null
}

query_value() {
    local query="$1"
    local key="$2"
    printf '%s\n' "$query" | awk -F ': *' -v key="$key" '$1 == key {print $2; exit}'
}

require_pwned_xr_dfu() {
    local query
    query="$(irecovery_query || true)"

    if [[ "$(query_value "$query" MODE)" != "DFU" ]]; then
        echo "[!] Put the iPhone XR in DFU mode, pwn it with usbliter8, reconnect it, then retry." >&2
        return 1
    fi
    if [[ "$(query_value "$query" PRODUCT)" != "iPhone11,8" ]]; then
        echo "[!] This nonce path currently supports only iPhone XR (iPhone11,8)." >&2
        return 1
    fi
    if [[ "$(query_value "$query" PWND)" != "usbliter8" ]]; then
        echo "[!] The iPhone XR is in DFU, but it is not pwned by usbliter8." >&2
        return 1
    fi
}

set_nonce() {
    local requested="$1"
    local patched_ibss="$2"
    local return_to_normal="$3"
    ensure_pyusb

    if [[ -z "$patched_ibss" ]]; then
        prepare_nonce_ibss
        patched_ibss="$NONCE_IBSS_PATCHED"
    elif [[ ! -s "$patched_ibss" ]]; then
        echo "[!] Supplied raw patched iBSS does not exist: $patched_ibss" >&2
        return 1
    fi

    require_pwned_xr_dfu

    local args=(set "$requested" --image "$patched_ibss" --record-dir "$NONCE_RECORDS")
    if [[ "$return_to_normal" == "1" ]]; then
        args+=(--boot-normal)
    fi
    "$PYTHON_BIN" "$NONCECTL" "${args[@]}"

    echo "[+] Generator and entangled APNonce verified."
    if [[ "$return_to_normal" != "1" ]]; then
        echo "[+] Run $SCRIPT_DIR/bin/irecovery -n to boot into normal mode."
    fi
}

main() {
    local action="${1:-}"
    if [[ -z "$action" ]]; then
        usage
        return 1
    fi
    shift

    case "$action" in
        set)
            if [[ $# -lt 1 ]]; then
                usage
                return 1
            fi
            local generator
            generator="$(resolve_caller_path "$1")"
            local ibss=""
            local return_to_normal=0
            shift
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --ibss)
                        [[ $# -ge 2 ]] || { usage; return 1; }
                        ibss="$(resolve_caller_path "$2")"
                        shift 2
                        ;;
                    --boot-normal)
                        return_to_normal=1
                        shift
                        ;;
                    *)
                        usage
                        return 1
                        ;;
                esac
            done
            set_nonce "$generator" "$ibss" "$return_to_normal"
            ;;
        *)
            usage
            return 1
            ;;
    esac
}

main "$@"
