#!/usr/bin/env bash

set -e

# this is inverted because docker build takes "--no-cache",
# so "false" here means that the layer cache will be used
no_layer_cache=false

function build_docker_image_fixture {
  image_name="$1"
  output_tar="cmd/osv-scanner/scan/image/testdata/$image_name.tar"

  if [ ! -f "$output_tar" ]; then
    docker build cmd/osv-scanner/scan/image/testdata/ -f "cmd/osv-scanner/scan/image/testdata/$image_name.Dockerfile" -t "osv-scanner/$image_name:latest" --no-cache="$no_layer_cache"
    docker image save "osv-scanner/$image_name:latest" -o "$output_tar"

    echo "finished building $output_tar (did not exist)"
  else
    echo "skipped building $output_tar (already exists)"
  fi
}

force=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --force)
      force=true
      shift
      ;;
    --no-cache)
      no_layer_cache=true
      shift
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

for dockerfile in cmd/osv-scanner/scan/image/testdata/*.Dockerfile; do
  image_name=$(basename "$dockerfile" .Dockerfile)

  if [ "$force" = true ]; then
    echo "Removing existing tar file for $image_name..."
    rm "cmd/osv-scanner/scan/image/testdata/$image_name.tar"
  fi

  build_docker_image_fixture "$image_name"
done
