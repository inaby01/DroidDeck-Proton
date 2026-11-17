# DroidDeck's pinned runtime source uses Ubuntu 26.04 LTS / arm64.
# Registry digest fixes the official base, not the subsequently fetched apt packages.
FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db
RUN test "$(dpkg --print-architecture)" = arm64 \
    && apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1 HOME=/root
COPY input/ /input/
