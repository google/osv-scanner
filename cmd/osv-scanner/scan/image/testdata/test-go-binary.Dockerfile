FROM golang:1.22.4-alpine3.20@sha256:ace6cc3fe58d0c7b12303c57afe6d6724851152df55e08057b43990b927ad5e8 AS build

COPY package-tracing-fixture/ /work

RUN cd /work && go get github.com/BurntSushi/toml@v1.4.0 && go mod tidy
RUN cd /work && go build .
RUN cp /work/ptf /work/ptf-1.4.0

FROM alpine:3.20.1@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0

COPY --from=build /work/ptf-1.4.0 /go/bin/
