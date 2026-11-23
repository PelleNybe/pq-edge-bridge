#!/usr/bin/env bash
# Reproducible build & install script for liboqs (C library) and liboqs-python.
# Supports Linux x86_64 and ARM64 (e.g., Raspberry Pi 5 / Jetson / AWS Graviton).

set -euo pipefail

LIBOQS_VERSION="${LIBOQS_VERSION:-0.16.0}"
LIBOQS_PYTHON_SPEC="${LIBOQS_PYTHON_SPEC:-liboqs-python>=0.16.0,<0.17.0}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
BUILD_DIR="${BUILD_DIR:-/tmp/liboqs-build}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SKIP_APT="${SKIP_APT:-0}"

ARCH="$(uname -m)"
echo "[pq-edge-bridge] Detected architecture: ${ARCH}"
echo "[pq-edge-bridge] Installing liboqs ${LIBOQS_VERSION} to ${INSTALL_PREFIX}"

if [[ "${SKIP_APT}" != "1" ]] && command -v apt-get >/dev/null 2>&1; then
    SUDO=""
    if [[ "$(id -u)" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
    echo "[pq-edge-bridge] Installing build dependencies via apt-get..."
    ${SUDO} apt-get update -qq
    ${SUDO} apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git libssl-dev ca-certificates
fi

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

echo "[pq-edge-bridge] Cloning liboqs ${LIBOQS_VERSION}..."
git clone --depth 1 --branch "${LIBOQS_VERSION}" \
    https://github.com/open-quantum-safe/liboqs.git "${BUILD_DIR}/liboqs"

CMAKE_EXTRA_FLAGS=()
if [[ "${ARCH}" == "aarch64" || "${ARCH}" == "arm64" ]]; then
    # Enable portable ARMv8-A crypto extensions where available without breaking generic arm64
    CMAKE_EXTRA_FLAGS+=("-DOQS_DIST_BUILD=ON")
else
    CMAKE_EXTRA_FLAGS+=("-DOQS_DIST_BUILD=ON")
fi

GENERATOR="Unix Makefiles"
if command -v ninja >/dev/null 2>&1; then
    GENERATOR="Ninja"
fi

echo "[pq-edge-bridge] Configuring liboqs with CMake (${GENERATOR})..."
cmake -S "${BUILD_DIR}/liboqs" -B "${BUILD_DIR}/liboqs/build" \
    -G "${GENERATOR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_USE_OPENSSL=ON \
    "${CMAKE_EXTRA_FLAGS[@]}"

NPROC="$(nproc 2>/dev/null || echo 4)"
echo "[pq-edge-bridge] Compiling liboqs using ${NPROC} cores..."
cmake --build "${BUILD_DIR}/liboqs/build" --parallel "${NPROC}"

echo "[pq-edge-bridge] Installing liboqs to ${INSTALL_PREFIX}..."
if [[ -w "${INSTALL_PREFIX}" ]]; then
    cmake --install "${BUILD_DIR}/liboqs/build"
elif command -v sudo >/dev/null 2>&1; then
    sudo cmake --install "${BUILD_DIR}/liboqs/build"
else
    echo "ERROR: ${INSTALL_PREFIX} is not writable and sudo is unavailable." >&2
    exit 1
fi

if command -v ldconfig >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
    ldconfig
fi

echo "[pq-edge-bridge] Installing ${LIBOQS_PYTHON_SPEC}..."
"${PYTHON_BIN}" -m pip install --no-cache-dir "${LIBOQS_PYTHON_SPEC}"

echo "[pq-edge-bridge] Verifying ML-KEM-768 and ML-DSA-65..."
LD_LIBRARY_PATH="${INSTALL_PREFIX}/lib:${INSTALL_PREFIX}/lib64:${LD_LIBRARY_PATH:-}" \
    "${PYTHON_BIN}" -c "
import oqs
assert 'ML-KEM-768' in oqs.get_enabled_kem_mechanisms(), 'ML-KEM-768 missing'
assert 'ML-DSA-65' in oqs.get_enabled_sig_mechanisms(), 'ML-DSA-65 missing'
print('Verified liboqs:', oqs.oqs_version())
"

rm -rf "${BUILD_DIR}"
echo "[pq-edge-bridge] liboqs installation complete."
