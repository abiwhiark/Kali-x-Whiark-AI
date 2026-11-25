#!/usr/bin/env bash
# Kali x Whiark AI — Local Ollama Cybersecurity Setup Script for Kali Linux
# Usage:
#   chmod +x ollama/install_kali_ollama.sh
#   ./ollama/install_kali_ollama.sh              # Default: kali-cyber (qwen2.5:7b, ~4.7GB)
#   ./ollama/install_kali_ollama.sh pro          # High-RAM/GPU: kali-cyber-pro (qwen2.5:14b, ~9GB)
#   ./ollama/install_kali_ollama.sh whiterabbit  # Community cyber fine-tune via HuggingFace/Ollama

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
VARIANT="${1:-default}"

echo "============================================================"
echo "  ⚡ KALI x WHIARK AI — Local Ollama Cybersecurity Installer"
echo "============================================================"

# 1. Install Ollama if not present
if ! command -v ollama >/dev/null 2>&1; then
    echo "[1/4] Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "[1/4] Ollama already installed: $(ollama --version)"
fi

# 2. Start Ollama service / daemon if not listening
echo "[2/4] Ensuring Ollama server is running on 127.0.0.1:11434..."
if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "^ollama.service"; then
        sudo systemctl enable --now ollama || true
    fi
    if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
        nohup ollama serve >/tmp/ollama.log 2>&1 &
        sleep 3
    fi
fi

# Wait until Ollama responds
for i in $(seq 1 15); do
    if curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# 3. Pull / create cybersecurity model
echo "[3/4] Setting up cybersecurity model (variant: $VARIANT)..."
case "$VARIANT" in
    pro)
        MODEL_NAME="kali-cyber-pro"
        ollama pull qwen2.5:14b
        ollama create "$MODEL_NAME" -f "$SCRIPT_DIR/Modelfile.kali-cyber-pro"
        ;;
    lily)
        MODEL_NAME="hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF"
        ollama pull "$MODEL_NAME"
        ;;
    whiterabbit)
        MODEL_NAME="deephat"
        ollama pull "$MODEL_NAME"
        ;;
    *)
        MODEL_NAME="kali-cyber"
        ollama pull qwen2.5:7b
        ollama create "$MODEL_NAME" -f "$SCRIPT_DIR/Modelfile.kali-cyber"
        ;;
esac

# 4. Configure .env for local Ollama
echo "[4/4] Configuring $ENV_FILE for Ollama ($MODEL_NAME)..."
if [ ! -f "$ENV_FILE" ] && [ -f "$REPO_ROOT/.env.example" ]; then
    cp "$REPO_ROOT/.env.example" "$ENV_FILE"
fi
touch "$ENV_FILE"

set_env_var() {
    local key="$1"
    local val="$2"
    if grep -qE "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
    else
        echo "${key}=${val}" >> "$ENV_FILE"
    fi
}

set_env_var "ACTIVE_PROVIDER" "ollama"
set_env_var "OLLAMA_HOST" "http://127.0.0.1:11434"
set_env_var "OLLAMA_MODEL" "$MODEL_NAME"
set_env_var "ALLOWED_TARGETS" "*"

echo ""
echo "✔ Setup complete! Model ready: $MODEL_NAME"
echo "Run Kali AI locally with:"
echo "  cd \"$REPO_ROOT\" && source venv/bin/activate && python3 cli.py"
