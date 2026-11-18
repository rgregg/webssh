FROM python:3-alpine AS builder

RUN apk add --no-cache libc-dev libffi-dev gcc

COPY requirements.txt /tmp/requirements.txt
RUN pip install --prefix=/install --no-cache-dir -r /tmp/requirements.txt


# tailcat, for Tailcat hosts (see docs/tailcat.md). Pinned to one release
# and checked against the SHA-256 sums published in that release's
# checksums.txt, so a re-tagged or tampered download fails the build. To
# upgrade: change TAILCAT_VERSION and all three sums together, and re-run
# the tailcat tests (TAILCAT_BIN=... pytest tests/test_tailcat.py).
FROM python:3-alpine AS tailcat

ARG TARGETARCH
ENV TAILCAT_VERSION=0.7.0

RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=amd64; sum=23c0b1887a5ec422f0d18a9c52b4f5357815febdaae738a1eb54036d10bd9ee6 ;; \
      arm64) arch=arm64; sum=bbb1ab50f24f00effe1e1fd86d0501803fb80793a90785a2a16ff3428f03d8ef ;; \
      arm)   arch=armv7; sum=cad3994b1f336b67e8a3a5273a9cecb44331d14d57eb32bfe7d0919adeab22b7 ;; \
      *) echo "no pinned tailcat build for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    file="tailcat_${TAILCAT_VERSION}_linux_${arch}.tar.gz"; \
    wget -q -O "/tmp/${file}" \
      "https://github.com/tailscale/tailcat/releases/download/v${TAILCAT_VERSION}/${file}"; \
    echo "${sum}  /tmp/${file}" | sha256sum -c -; \
    tar -xzf "/tmp/${file}" -C /tmp tailcat; \
    install -m 0755 /tmp/tailcat /usr/local/bin/tailcat; \
    test "$(/usr/local/bin/tailcat --version)" = "v${TAILCAT_VERSION}"


FROM python:3-alpine

ARG VERSION=dev

LABEL maintainer='<author>'
LABEL version=${VERSION}

COPY --from=builder /install /usr/local
COPY --from=tailcat /usr/local/bin/tailcat /usr/local/bin/tailcat

RUN addgroup -g 1000 webssh && \
    adduser -u 1000 -Ss /bin/false -g webssh webssh && \
    mkdir -p -m 700 /data/user-keys && \
    chown webssh:webssh /data/user-keys

COPY . /code
WORKDIR /code

# Bake the version into the fallback so git is not needed at runtime
RUN sed -i "s/^FALLBACK_VERSION = .*/FALLBACK_VERSION = '${VERSION}'/" webssh/_version.py && \
    chown -R webssh:webssh /code

EXPOSE 8888/tcp
USER webssh
CMD ["python", "run.py"]
