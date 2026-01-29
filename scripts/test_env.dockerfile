FROM golang:1.25.5-alpine3.21@sha256:b4dbd292a0852331c89dfd64e84d16811f3e3aae4c73c13d026c4d200715aff6

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
