# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.22.5-alpine3.19@sha256:0642d4f809abf039440540de1f0e83502401686e3946ed8e7398a1d94648aa6d

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o osv-scanner ./cmd/osv-scanner/
RUN go build -o osv-reporter ./cmd/osv-reporter/

FROM alpine:3.20@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0
RUN apk --no-cache add \
  ca-certificates \
  git \
  bash

# Allow git to run on mounted directories
RUN git config --global --add safe.directory '*'

WORKDIR /root/
COPY --from=0 /src/osv-scanner ./
COPY --from=0 /src/osv-reporter ./
COPY ./exit_code_redirect.sh ./

ENV PATH="${PATH}:/root"

ENTRYPOINT ["bash", "/root/exit_code_redirect.sh"]
