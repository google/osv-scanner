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

# Use the alpine version of the golang image as the base image
FROM golang:alpine

# Create a directory named '/src' and set it as the working directory
RUN mkdir /src
WORKDIR /src

# Copy the go.mod and go.sum files from the host machine to the '/src' directory in the container
COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum

# Download the required Go modules
RUN go mod download

# Copy all the files from the host machine to the '/src' directory in the container
COPY ./ /src/

# Build the Go binary for the 'osv-scanner' command and save it as 'osv-scanner' in the '/src' directory
RUN go build -o osv-scanner ./cmd/osv-scanner/

# Use the alpine version of the base image
FROM alpine:latest

# Install the 'ca-certificates' and 'git' packages
RUN apk --no-cache add \
    ca-certificates \
    git

# Allow git to run on mounted directories
RUN git config --global --add safe.directory '*'

# Set '/root/' as the working directory and copy the 'osv-scanner' binary from the previous image to '/root/'
WORKDIR /root/
COPY --from=0 /src/osv-scanner ./

# Set the 'osv-scanner' binary as the entrypoint for the container
ENTRYPOINT ["/root/osv-scanner"]

