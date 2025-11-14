FROM alpine:latest

RUN apk add curl
RUN cd /tmp && curl -LO  https://launchpad.net/~ubuntu-security/+archive/ubuntu/ubuntu-security-golang-rebuilds/+build/29277135/+files/fzf_0.29.0-1ubuntu0.1_amd64.deb

FROM ubuntu:22.04@sha256:ed1544e454989078f5dec1bfdabd8c5cc9c48e0705d07b678ab6ae3fb61952d2

# Install fzf from a existing build to keep it pinned to a specific version
COPY --from=0 /tmp/fzf_0.29.0-1ubuntu0.1_amd64.deb /tmp
RUN dpkg -i /tmp/fzf_0.29.0-1ubuntu0.1_amd64.deb && rm /tmp/fzf_0.29.0-1ubuntu0.1_amd64.deb

