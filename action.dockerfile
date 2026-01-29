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

# WARNING, this workflow is for legacy purposes. To view the current workflow see: https://github.com/google/osv-scanner-action
FROM golang:1.25.5-alpine3.21@sha256:b4dbd292a0852331c89dfd64e84d16811f3e3aae4c73c13d026c4d200715aff6

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o osv-scanner ./cmd/osv-scanner/
RUN go build -o osv-reporter ./cmd/osv-reporter/

FROM alpine:3.23
RUN apk upgrade --no-cache && \
  apk add --no-cache \
    ca-certificates \
    git \
    bash && \
  git config --global --add safe.directory '*'
FROM alpine:3.23@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62
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

ENTRYPOINT [
  "bash",
  "-c",
  "echo 'WARNING, this workflow is for legacy purposes. To view the current workflow see: https://github.com/google/osv-scanner-action' && /root/exit_code_redirect.sh"
]
