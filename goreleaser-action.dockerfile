# Copyright 2024 Google LLC
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

FROM alpine:3.21@sha256:56fa17d2a7e7f168a043a2712e63aed1f8543aeafdcee47c58dcffe38ed51099
RUN apk --no-cache add \
  ca-certificates \
  git \
  bash \
  go

# Allow git to run on mounted directories
RUN git config --global --add safe.directory '*'

# Built binaries provided by goreleaser
WORKDIR /root/
COPY ./osv-scanner-action ./osv-scanner
COPY ./osv-reporter ./
COPY ./exit_code_redirect.sh ./

ENV PATH="${PATH}:/root"

ENTRYPOINT ["bash", "/root/exit_code_redirect.sh"]
