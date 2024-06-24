FROM golang:1.22.4-alpine3.20@sha256:ace6cc3fe58d0c7b12303c57afe6d6724851152df55e08057b43990b927ad5e8

# Install old version of osv-scanner (1.3.0)
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@cfe6d7502821f60c09be0f6de2548ac952b01696

# This tests when a file that exists in the final layer doesn't exist in an intermediate layer
RUN mv /go/bin/osv-scanner /go/bin/osv-scanner-1.3.0

# These lines test when a file only exist in a intermediate layer
RUN cp /go/bin/osv-scanner-1.3.0 /go/bin/osv-scanner-1.3.0-copy
RUN rm /go/bin/osv-scanner-1.3.0-copy

# Install a newer version of osv-scanner (1.8.1)
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@46aee59befed6edb5fc737ef35b5febf987cffa9

# Overwrite with older version of osv-scanner (1.5.0)
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@060799ca816dfa40afa05e48c895c0c9fd79b90b

