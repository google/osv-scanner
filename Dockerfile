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

FROM golang:alpine@sha256:74a382917f6eaa7cc2d000dc2cd412a7f823f343b3b6268b20d84d057bc56718

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o osv-scanner ./cmd/osv-scanner/

FROM alpine:3.17@sha256:ff6bdca1701f3a8a67e328815ff2346b0e4067d32ec36b7992c1fdc001dc8517
RUN apk --no-cache add \
    ca-certificates \
    git

# Allow git to run on mounted directories
RUN git config --global --add safe.directory '*'

WORKDIR /root/
COPY --from=0 /src/osv-scanner ./

ENTRYPOINT ["/root/osv-scanner"]
