# Base image for the add-auth Cloud Agent environment.
# Provides Node.js 22, PostgreSQL 16, and Redis 7 — the runtime services
# the auth library and its example apps require.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# System packages: PostgreSQL 16 + Redis (default in Ubuntu 24.04 repos),
# plus toolchain needed to build native npm deps (e.g. bcrypt).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        git \
        sudo \
        build-essential \
        python3 \
        postgresql-16 \
        postgresql-contrib \
        redis-server \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22 via NodeSource.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# The ubuntu:24.04 image ships a non-root "ubuntu" user (uid 1000).
# Grant passwordless sudo so the start script can manage postgres/redis.
RUN echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu \
    && chmod 0440 /etc/sudoers.d/ubuntu

USER ubuntu
