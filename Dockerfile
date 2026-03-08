FROM python:3-alpine AS builder

RUN apk add --no-cache libc-dev libffi-dev gcc

COPY requirements.txt /tmp/requirements.txt
RUN pip install --prefix=/install --no-cache-dir -r /tmp/requirements.txt


FROM python:3-alpine

ARG VERSION=dev

LABEL maintainer='<author>'
LABEL version=${VERSION}

COPY --from=builder /install /usr/local

RUN addgroup webssh && \
    adduser -Ss /bin/false -g webssh webssh && \
    mkdir -p /data/user-keys && \
    chown webssh:webssh /data/user-keys

COPY . /code
WORKDIR /code

# Bake the version into the fallback so git is not needed at runtime
RUN sed -i "s/^FALLBACK_VERSION = .*/FALLBACK_VERSION = '${VERSION}'/" webssh/_version.py && \
    chown -R webssh:webssh /code

EXPOSE 8888/tcp
USER webssh
CMD ["python", "run.py"]
