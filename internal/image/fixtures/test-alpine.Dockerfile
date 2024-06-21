FROM alpine:3.10@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98

# Switch the version to 3.19 to show the advisories published for the latest alpine versions
COPY "alpine-3.19-alpine-release" "/etc/alpine-release"
