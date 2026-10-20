FROM golang:1.27.3-alpine3.23@sha256:895e5feab11a4b3774d24ee3c9579028456b82ad37f42a9eb6f82adaf776a201

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
