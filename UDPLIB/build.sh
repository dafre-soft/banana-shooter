#!/usr/bin/env bash
# ============================================================
#  build.sh - сборка UDPLIB + prepatcher + Unity-модуль,
#             НУМЕРАЦИЯ БИЛДА (build-файл и скрипт в одном файле)
#
#  Правила нумерации:
#    - номер сборки хранится в .build (в каталоге UDPLIB);
#    - если файла .build нет или он пуст/битый -> билд = 1;
#    - каждая успешная сборка инкрементирует номер.
#
#  Использование:
#    ./build.sh [команды]
#      (без команд)   собрать всё доступное для текущей платформы
#      test           прогнать unit/протокольные тесты
#      linux          собрать libudplib.so + prepatcher (Linux)
#      windows        собрать udplib.dll + prepatcher.exe (cross-mingw)
#      unity          скопировать C#-модуль в ../Assets/UDPLIB
#      clean          удалить build/ и dist/
#      --no-bump      не увеличивать номер сборки
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT/src"
BUILD="$ROOT/build"
DIST="$ROOT/dist"
TEST="$ROOT/test"
PREP="$ROOT/prepatcher"
CSHARP="$ROOT/csharp"

# ---------- загрузка конфигурации версии ----------
VERSION_MAJOR=1; VERSION_MINOR=0; VERSION_PATCH=0
PRODUCT_NAME="UDPLIB"; UDP_PORT=27777; MAX_UDP_CLIENTS=8
UDPLIB_PASSWORD=""; UDPLIB_PASSWORD_HASH=""
if [[ -f "$ROOT/version.conf" ]]; then
    # shellcheck disable=SC1090
    source "$ROOT/version.conf"
fi

# ---------- нумерация билда ----------
read_build_number() {
    if [[ -f "$ROOT/.build" ]]; then
        local n
        n="$(tr -dc '0-9' < "$ROOT/.build" || true)"
        if [[ -n "$n" ]]; then echo "$n"; return; fi
    fi
    echo "0"   # 0 означает "ещё не собиралось" -> следующий будет 1
}
next_build_number() {
    local cur next
    cur="$(read_build_number)"
    next=$((cur + 1))
    printf '%s\n' "$next" > "$ROOT/.build"
    echo "$next"
}

BUMP=1
for arg in "$@"; do [[ "$arg" == "--no-bump" ]] && BUMP=0; done
if [[ $BUMP -eq 1 ]]; then
    BUILD_NUM="$(next_build_number)"
else
    BUILD_NUM="$(read_build_number)"
    [[ "$BUILD_NUM" == "0" ]] && BUILD_NUM=1
fi
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "============================================================"
echo " UDPLIB V${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}"
echo " Build ${BUILD_NUM} from ${BUILD_DATE}"
echo "============================================================"

mkdir -p "$BUILD" "$DIST"

# ---------- пароль: plain -> SHA-256 hex ----------
# Приоритет: готовый хэш в version.conf; иначе считаем из UDPLIB_PASSWORD.
if [[ -z "$UDPLIB_PASSWORD_HASH" && -n "$UDPLIB_PASSWORD" ]]; then
    if command -v sha256sum >/dev/null; then
        UDPLIB_PASSWORD_HASH="$(printf '%s' "$UDPLIB_PASSWORD" | sha256sum | cut -d' ' -f1)"
    else
        UDPLIB_PASSWORD_HASH="$(printf '%s' "$UDPLIB_PASSWORD" | shasum -a 256 | cut -d' ' -f1)"
    fi
fi
if [[ -z "$UDPLIB_PASSWORD_HASH" ]]; then
    echo "[WARN] пароль не задан: вход UDP-клиентов будет запрещён." >&2
fi

DEFINES=(
    "-DUDPLIB_VERSION_MAJOR=${VERSION_MAJOR}"
    "-DUDPLIB_VERSION_MINOR=${VERSION_MINOR}"
    "-DUDPLIB_VERSION_PATCH=${VERSION_PATCH}"
    "-DUDPLIB_BUILD_NUMBER=${BUILD_NUM}"
    "-DUDPLIB_BUILD_DATE=\"${BUILD_DATE}\""
    "-DUDPLIB_PRODUCT_NAME=\"${PRODUCT_NAME}\""
    "-DUDPLIB_UDP_PORT=${UDP_PORT}"
    "-DUDPLIB_MAX_CLIENTS=${MAX_UDP_CLIENTS}"
    "-DUDPLIB_PASSWORD_HASH=\"${UDPLIB_PASSWORD_HASH}\""
)
CXXFLAGS=(-O2 -std=c++17 -Wall -Wextra -fPIC "${DEFINES[@]}")

LIB_SOURCES=("$SRC/udplib_api.cpp" "$SRC/udplib_server.cpp" "$SRC/sha256.c")
PREP_SOURCES=("$PREP/main.c" "$SRC/sha256.c")

have_linux_gcc() { command -v g++ >/dev/null && command -v gcc >/dev/null; }
have_mingw()     { command -v x86_64-w64-mingw32-g++-posix >/dev/null; }

build_tests() {
    echo "--- [test] sha256 vectors ---"
    gcc -O2 -Wall -Wextra -fsanitize=address,undefined -o "$BUILD/sha_test" \
        "$TEST/sha_test.c" "$SRC/sha256.c"
    "$BUILD/sha_test"

    echo "--- [test] protocol host (libudplib + client smoke) ---"
    g++ "${CXXFLAGS[@]}" -o "$BUILD/host_main" "$TEST/host_main.cpp" \
        "${LIB_SOURCES[@]}" -lpthread -fsanitize=address,undefined
    g++ -O2 -std=c++17 -Wall -Wextra -o "$BUILD/udp_client" "$TEST/udp_client.cpp" "${DEFINES[@]}"
    LD_PRELOAD="$BUILD/libudplib_asan.so" true  # no-op, чтобы set -e не спотыкалось
}

build_linux_lib() {
    echo "--- [linux] libudplib.so ---"
    gcc -O2 -Wall -Wextra -fPIC -c "$SRC/sha256.c" -o "$BUILD/sha256.o" "${DEFINES[@]}"
    g++ "${CXXFLAGS[@]}" -shared -o "$DIST/libudplib.so" \
        "$SRC/udplib_api.cpp" "$SRC/udplib_server.cpp" "$BUILD/sha256.o" -lpthread
    cp "$DIST/libudplib.so" "$BUILD/libudplib_asan.so"
    echo "    -> $DIST/libudplib.so"
}

build_linux_prepatcher() {
    echo "--- [linux] prepatcher (ELF) ---"
    gcc -O2 -Wall -Wextra -o "$DIST/prepatcher" "${PREP_SOURCES[@]}"
    echo "    -> $DIST/prepatcher"
}

build_windows_lib() {
    echo "--- [windows] udplib.dll (mingw posix-threads) ---"
    x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -c "$SRC/sha256.c" -o "$BUILD/sha256.obj" "${DEFINES[@]}"
    x86_64-w64-mingw32-g++-posix "${CXXFLAGS[@]}" -shared -static -static-libgcc -static-libstdc++ \
        -o "$DIST/udplib.dll" "$SRC/udplib_api.cpp" "$SRC/udplib_server.cpp" "$BUILD/sha256.obj" -lws2_32 -m64
    echo "    -> $DIST/udplib.dll"
}

build_windows_prepatcher() {
    echo "--- [windows] prepatcher.exe ---"
    x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -m64 -o "$DIST/prepatcher.exe" \
        "${PREP_SOURCES[@]}" -static
    echo "    -> $DIST/prepatcher.exe"
}

build_unity_module() {
    echo "--- [unity] managed module -> Assets/UDPLIB ---"
    local assets="../Assets/UDPLIB"
    mkdir -p "$assets/Plugins/x86_64" "$assets/Plugins/Linux/x86_64"
    cp -f "$CSHARP"/*.cs "$assets/"
    [[ -f "$DIST/udplib.dll" ]] && cp -f "$DIST/udplib.dll" "$assets/Plugins/x86_64/"
    [[ -f "$DIST/libudplib.so" ]] && cp -f "$DIST/libudplib.so" "$assets/Plugins/Linux/x86_64/"
    echo "    -> $assets"
}

CMDS=(); for a in "$@"; do case "$a" in --*) ;; *) CMDS+=("$a");; esac; done

if [[ ${#CMDS[@]} -eq 0 ]]; then
    have_linux_gcc && { build_linux_lib; build_linux_prepatcher; }
    have_mingw && { build_windows_lib; build_windows_prepatcher; }
    build_tests
    build_unity_module
else
    for c in "${CMDS[@]}"; do
        case "$c" in
            test)      build_tests ;;
            linux)     have_linux_gcc && { build_linux_lib; build_linux_prepatcher; } || echo "[skip] нет g++" ;;
            windows)   have_mingw && { build_windows_lib; build_windows_prepatcher; } || echo "[skip] нет mingw" ;;
            unity)     build_unity_module ;;
            clean)     rm -rf "$BUILD" "$DIST"; mkdir -p "$BUILD" "$DIST"; echo "cleaned" ;;
            *) echo "неизвестная команда: $c" >&2; exit 2 ;;
        esac
    done
fi

# ---------- манифест дистрибутива (sha256 артефактов) ----------
{
    echo "version=${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}"
    echo "build=${BUILD_NUM}"
    echo "date=${BUILD_DATE}"
    for f in "$DIST"/*; do
        [[ -f "$f" ]] && echo "sha256($(basename "$f"))=$(sha256sum "$f" | cut -d' ' -f1)"
    done
} > "$DIST/manifest.txt"
echo "--- manifest: $DIST/manifest.txt ---"
cat "$DIST/manifest.txt"
echo "BUILD OK: UDPLIB V${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH} / Build ${BUILD_NUM} from ${BUILD_DATE}"
