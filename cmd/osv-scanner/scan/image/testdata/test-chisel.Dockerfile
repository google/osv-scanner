FROM ubuntu:26.04@sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64 AS builder

RUN apt install --update -y curl wget

# Deb arch to GOARCH
RUN arch="$(dpkg --print-architecture | sed -e 's/armhf/arm/g' -e 's/ppc64el/ppc64le/g')" && \
    curl -s https://api.github.com/repos/canonical/chisel/releases/latest \
        | awk "/browser_download_url/ && /chisel_v/ && /_$arch\./" \
        | cut -d : -f 2,3 \
        | tr -d \" \
        | xargs wget

RUN sha384sum -c chisel_v*sha384
RUN tar -xf chisel_v*tar.gz -C /usr/local/bin
RUN mkdir /rootfs && \
    chisel cut --root /rootfs \
        base-files_base \
        base-files_chisel \
        base-files_release-info \
        golang_core

FROM scratch
COPY --from=builder /rootfs/ /
