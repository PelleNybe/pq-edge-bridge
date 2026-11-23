# Multi-stage, multi-arch (linux/amd64, linux/arm64) Dockerfile for pq-edge-bridge.
# Compiles liboqs 0.16.0 from source in the builder stage and copies only runtime artifacts.

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ARG LIBOQS_VERSION=0.16.0

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs shared library to /opt/liboqs
RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" \
        https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_USE_OPENSSL=ON \
        -DOQS_DIST_BUILD=ON && \
    cmake --build /tmp/liboqs/build --parallel "$(nproc)" && \
    cmake --install /tmp/liboqs/build && \
    rm -rf /tmp/liboqs

WORKDIR /build
COPY pyproject.toml LICENSE README.md ./
COPY src ./src

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir .


FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* && \
    groupadd --system pqbridge && \
    useradd --system --gid pqbridge --create-home --home-dir /var/lib/pq-edge-bridge pqbridge

COPY --from=builder /opt/liboqs/lib /usr/local/lib
COPY --from=builder /opt/venv /opt/venv
RUN ldconfig

ENV PATH="/opt/venv/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/local/lib" \
    PYTHONUNBUFFERED=1

USER pqbridge
WORKDIR /var/lib/pq-edge-bridge

ENTRYPOINT ["pq-edge-bridge"]
CMD ["--help"]
