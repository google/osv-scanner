FROM alpine:3.10

# Switch the version to 3.19 to show the advisories published for the latest alpine versions
COPY "alpine-3.19-alpine-release" "/etc/alpine-release"
