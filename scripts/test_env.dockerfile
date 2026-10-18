FROM golang:1.27.2-alpine3.23@sha256:9e45f0eb4a63ed37ad6e604950407558b7c738e34e015ae77a5d4ad369cde079

RUN apk --no-cache add \
  npm \
  maven \
  docker-cli \
  git \
  build-base \
  bash \
  rust \
  cargo

WORKDIR /src
