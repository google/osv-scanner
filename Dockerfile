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

FROM golang:alpine@sha256:926f7f7e1ab8509b4e91d5ec6d5916ebb45155b0c8920291ba9f361d65385806 AS builder

WORKDIR /src
COPY ./go.mod ./go.sum ./
RUN go mod download

COPY ./ ./
RUN go build -o osv-scanner ./cmd/osv-scanner/

FROM alpine:3.18@sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978

RUN apk --no-cache add ca-certificates git && \
    git config --global --add safe.directory '*'

WORKDIR /root/
COPY --from=builder /src/osv-scanner .

ENTRYPOINT ["/root/osv-scanner"]
