FROM ghcr.io/homebrew/ubuntu22.04:5.1.4@sha256:6b3c4bc0a7128cf5a78d2e641da6e88ac4195714e1315c4d2b522532d7fb1e7a

USER linuxbrew
WORKDIR /home/linuxbrew

ENV HOMEBREW_NO_AUTO_UPDATE=1 \
    NONINTERACTIVE=1

# Install vulnerable package
RUN brew install cjson

# Make it vulnerable :)
RUN mv .linuxbrew/Cellar/cjson/* .linuxbrew/Cellar/cjson/1.7.17
