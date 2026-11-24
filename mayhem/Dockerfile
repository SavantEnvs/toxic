# syntax=docker/dockerfile:1.7
# Commit image for toxic (ncurses Tox client). Builds on the org base; adds the apt -dev libs
# toxic links against and a static c-toxcore v0.2.23 (Debian's 0.2.20 is too old for toxic HEAD).
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
        make cmake pkg-config git ca-certificates libsodium-dev libconfig-dev \
        libncurses-dev libcurl4-openssl-dev libgtest-dev \
 && rm -rf /var/lib/apt/lists/*

# c-toxcore v0.2.23 (commit d9ca3c5), static, uninstrumented, DWARF 3 (SPEC §6.2 item 19).
ARG TOXCORE_VER=0.2.23
ARG TOXCORE_COMMIT=d9ca3c577e5abd4303d180eb5270167b4133ea4c
RUN d=/opt/toolchains/deps/toxcore-${TOXCORE_VER} && mkdir -p "$d" \
 && git clone --recurse-submodules https://github.com/TokTok/c-toxcore "$d/src" \
 && cd "$d/src" && git checkout -q "$TOXCORE_COMMIT" && git submodule update --init --recursive \
 && [ "$(git rev-parse HEAD)" = "$TOXCORE_COMMIT" ] \
 && cmake -S "$d/src" -B /tmp/tc-build -DCMAKE_INSTALL_PREFIX="$d" -DENABLE_SHARED=OFF -DENABLE_STATIC=ON \
      -DBUILD_TOXAV=OFF -DBOOTSTRAP_DAEMON=OFF -DDHT_BOOTSTRAP=OFF -DAUTOTEST=OFF -DUNITTEST=OFF \
      -DBUILD_MISC_TESTS=OFF -DBUILD_FUN_UTILS=OFF -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-O2 -g -gdwarf-3" -DCMAKE_CXX_FLAGS="-O2 -g -gdwarf-3" -DCMAKE_INSTALL_LIBDIR=lib \
 && cmake --build /tmp/tc-build -j"$(nproc)" --target install \
 && rm -rf /tmp/tc-build && rm -f "$d"/lib/*.so* && chmod -R a+rX "$d"
ENV PKG_CONFIG_PATH=/opt/toolchains/deps/toxcore-0.2.23/lib/pkgconfig

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
