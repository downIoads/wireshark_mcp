#!/usr/bin/env bash
# Install / update the Wireshark MCP server and register it with MCP hosts.
# Idempotent — safe to re-run after pulling changes or editing the source.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv"
PY="${VENV_DIR}/bin/python"
MCP_NAME="wireshark"
SCOPE="${WIRESHARK_MCP_SCOPE:-user}"   # override with: WIRESHARK_MCP_SCOPE=local ./install.sh
LOCK_DIR="${PROJECT_DIR}/.install.lock"

msg() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*" >&2; }

take_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" >"${LOCK_DIR}/pid"
        trap 'rm -rf "$LOCK_DIR"' EXIT
        return
    fi

    local old_pid=""
    if [[ -r "${LOCK_DIR}/pid" ]]; then
        old_pid="$(<"${LOCK_DIR}/pid")"
    fi
    if [[ "$old_pid" =~ ^[0-9]+$ ]] && kill -0 "$old_pid" 2>/dev/null; then
        warn "Another install.sh is already running (pid ${old_pid}); exiting."
        exit 1
    fi

    warn "Removing stale install lock."
    rm -rf "$LOCK_DIR"
    mkdir "$LOCK_DIR"
    printf '%s\n' "$$" >"${LOCK_DIR}/pid"
    trap 'rm -rf "$LOCK_DIR"' EXIT
}

clean_python_env() {
    if [[ -n "${VIRTUAL_ENV:-}" && "${VIRTUAL_ENV}" != "${VENV_DIR}" ]]; then
        warn "Ignoring active virtualenv: ${VIRTUAL_ENV}"
        warn "Using project virtualenv: ${VENV_DIR}"
        unset VIRTUAL_ENV
    fi
    hash -r 2>/dev/null || true
}

wireshark_mcp_pids() {
    ps -eo pid=,args= | while read -r pid args; do
        [[ "$pid" == "$$" ]] && continue
        case "$args" in
            *"${PY} -m wireshark_mcp"*|*"${VENV_DIR}/bin/wireshark-mcp"*)
                printf '%s\n' "$pid"
                ;;
        esac
    done
}

stop_running_servers() {
    mapfile -t pids < <(wireshark_mcp_pids | sort -u)
    if (( ${#pids[@]} == 0 )); then
        return
    fi

    msg "Stopping existing Wireshark MCP server process(es): ${pids[*]}"
    kill -TERM "${pids[@]}" 2>/dev/null || true

    local deadline=$((SECONDS + 5))
    while (( SECONDS < deadline )); do
        local alive=()
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                alive+=("$pid")
            fi
        done
        if (( ${#alive[@]} == 0 )); then
            return
        fi
        sleep 0.2
    done

    warn "Force-stopping stuck Wireshark MCP process(es)."
    kill -KILL "${pids[@]}" 2>/dev/null || true
}

take_lock
clean_python_env
stop_running_servers

# 1. venv
if [[ ! -x "$PY" ]]; then
    msg "Creating venv at ${VENV_DIR}"
    python3 -m venv "$VENV_DIR"
fi

# 2. install / upgrade in editable mode
msg "Installing wireshark-mcp (editable) + dependencies"
"$PY" -m pip install --quiet --upgrade pip
"$PY" -m pip install --quiet --editable "$PROJECT_DIR"

# 3. smoke-import so we fail fast if the package is broken
msg "Verifying server imports cleanly"
"$PY" -c "from wireshark_mcp.server import mcp; \
print(f'   {len(mcp._tool_manager.list_tools())} tools, \
{len(mcp._resource_manager.list_resources()) + len(mcp._resource_manager.list_templates())} resources')"

# 4. register with known MCP hosts
if command -v claude >/dev/null 2>&1; then
    # Try to remove any stale registration first so the command path always
    # reflects the current venv. Failures are fine (e.g. it wasn't registered).
    claude mcp remove "$MCP_NAME" --scope "$SCOPE" >/dev/null 2>&1 || true
    claude mcp remove "$MCP_NAME" >/dev/null 2>&1 || true

    msg "Registering '${MCP_NAME}' with Claude Code (scope: ${SCOPE})"
    claude mcp add "$MCP_NAME" --scope "$SCOPE" -- "$PY" -m wireshark_mcp

    echo
    msg "Current registrations:"
    claude mcp list | sed 's/^/    /'
    echo
    msg "Toggle '${MCP_NAME}' in the Claude Code VS Code extension's MCP panel."
else
    warn "'claude' CLI not on PATH — skipping registration."
    warn "Run this once it's installed:"
    warn "  claude mcp add ${MCP_NAME} --scope ${SCOPE} -- ${PY} -m wireshark_mcp"
fi

if command -v codex >/dev/null 2>&1; then
    codex mcp remove "$MCP_NAME" >/dev/null 2>&1 || true

    msg "Registering '${MCP_NAME}' with Codex"
    codex mcp add "$MCP_NAME" -- "$PY" -m wireshark_mcp
else
    warn "'codex' CLI not on PATH — skipping registration."
    warn "Run this once it's installed:"
    warn "  codex mcp add ${MCP_NAME} -- ${PY} -m wireshark_mcp"
fi
