# Copyright 2022 Google LLC
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

FROM golang:alpine@sha256:fd9d9d7194ec40a9a6ae89fcaef3e47c47de7746dd5848ab5343695dbbd09f8c

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o osv-scanner ./cmd/osv-scanner/

FROM alpine:3.18@sha256:82d1e9d7ed48a7523bdebc18cf6290bdb97b82302a8a9c27d4fe885949ea94d1
RUN apk --no-cache add \
    ca-certificates \
    git

# Allow git to run on mounted directories
RUN git config --global --add safe.directory '*'

WORKDIR /root/
COPY --from=0 /src/osv-scanner ./

ENTRYPOINT ["/root/osv-scanner"]
