FROM ubuntu:22.04@sha256:ed1544e454989078f5dec1bfdabd8c5cc9c48e0705d07b678ab6ae3fb61952d2

ENV HOMEBREW_NO_AUTO_UPDATE=1 \
    NONINTERACTIVE=1 \
    PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"

RUN apt update && apt install -y curl git tree
RUN useradd -m -s /bin/bash linuxbrew

USER linuxbrew
WORKDIR /home/linuxbrew

RUN /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install vulnerable package
RUN brew install cjson

# Make it vulnerable :)
RUN mv .linuxbrew/Cellar/cjson/* .linuxbrew/Cellar/cjson/1.7.17

