FROM python:3-alpine

ARG VERSION=dev

LABEL maintainer='<author>'
LABEL version=${VERSION}

ADD . /code
WORKDIR /code

# Bake the version into the fallback so git is not needed at runtime
RUN sed -i "s/^FALLBACK_VERSION = .*/FALLBACK_VERSION = '${VERSION}'/" webssh/_version.py

RUN \
  apk add --no-cache libc-dev libffi-dev gcc && \
  pip install -r requirements.txt --no-cache-dir && \
  apk del gcc libc-dev libffi-dev && \
  addgroup webssh && \
  adduser -Ss /bin/false -g webssh webssh && \
  chown -R webssh:webssh /code

EXPOSE 8888/tcp
USER webssh
CMD ["python", "run.py"]
