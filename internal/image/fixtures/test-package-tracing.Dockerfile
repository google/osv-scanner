FROM golang:1.22.4-alpine3.20@sha256:ace6cc3fe58d0c7b12303c57afe6d6724851152df55e08057b43990b927ad5e8 AS build

COPY package-tracing-fixture/ /work

RUN cd /work && go get github.com/BurntSushi/toml@v1.4.0 && go mod tidy
RUN cd /work && go build .
RUN cp /work/ptf /work/ptf-1.4.0

RUN cd /work && go get github.com/BurntSushi/toml@v1.3.0 && go mod tidy
RUN cd /work && go build .
RUN cp /work/ptf /work/ptf-1.3.0

RUN cd /work && go get github.com/BurntSushi/toml@v1.2.0 && go mod tidy
RUN cd /work && go build .
RUN cp /work/ptf /work/ptf-1.2.0

# RUN go install github.com/google/osv-scanner/cmd/osv-scanner@v1.3.0
# RUN cp /go/bin/osv-scanner /go/bin/osv-scanner-1.3.0
# RUN go install github.com/google/osv-scanner/cmd/osv-scanner@v1.8.1
# RUN cp /go/bin/osv-scanner /go/bin/osv-scanner-1.8.1
# RUN go install github.com/google/osv-scanner/cmd/osv-scanner@v1.5.0
# RUN cp /go/bin/osv-scanner /go/bin/osv-scanner-1.5.0

FROM alpine:3.20.1@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0

COPY --from=build /work/ptf-1.2.0 /work/ptf-1.3.0 /work/ptf-1.4.0 /go/bin/

# This tests when a file that exists in the final layer doesn't exist in one intermediate layer
RUN mv /go/bin/ptf-1.3.0 /go/bin/ptf-1.3.0-moved
RUN cp /go/bin/ptf-1.3.0-moved /go/bin/ptf-1.3.0

# This tests when a file only exist in a intermediate layer
RUN cp /go/bin/ptf-1.3.0 /go/bin/ptf-1.3.0-copy
RUN rm /go/bin/ptf-1.3.0-copy

# This tests when a less vulnerable file overwrites a more vulnerable file
# This tests when a less vulnerable file overwrites a more vulnerable file
RUN cp /go/bin/ptf-1.3.0 /go/bin/ptf-vulnerable
RUN cp /go/bin/ptf-1.4.0 /go/bin/ptf-vulnerable

# This tests when a more vulnerable file overwrites a less vulnerable file
RUN cp /go/bin/ptf-1.4.0 /go/bin/more-vuln-overwrite-less-vuln
RUN cp /go/bin/ptf-1.2.0 /go/bin/more-vuln-overwrite-less-vuln

