FROM ubuntu:22.04@sha256:ed1544e454989078f5dec1bfdabd8c5cc9c48e0705d07b678ab6ae3fb61952d2

# Install fzf from a existing build to keep it pinned to a specific version
COPY ./sample-pkgs/fzf_0.29.0-1ubuntu0.1_amd64.deb /tmp/fzf_0.29.0-1ubuntu0.1_amd64.deb
RUN dpkg -i /tmp/fzf_0.29.0-1ubuntu0.1_amd64.deb && rm /tmp/fzf_0.29.0-1ubuntu0.1_amd64.deb

