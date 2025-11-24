FROM golang:1.25.4-alpine3.21@sha256:3289aac2aac769e031d644313d094dbda745f28af81cd7a94137e73eefd58b33

RUN apk --no-cache add \
  npm \
  maven \
  docker-cli \
  git \
  build-base \
  bash

WORKDIR /src
