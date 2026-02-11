FROM golang:1.25.7-alpine3.23

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
