#!/usr/bin/env bash

set -e

function build_docker_image_fixture {
  image_name="$1"
  output_tar="internal/image/fixtures/$image_name.tar"

  if [ ! -f "$output_tar" ]; then
    docker build internal/image/fixtures/ -f "internal/image/fixtures/$image_name.Dockerfile" -t "osv-scanner/$image_name:latest"
    docker image save "osv-scanner/$image_name:latest" -o "$output_tar"

    echo "finished building $output_tar (did not exist)"
  else
    echo "skipped building $output_tar (already exists)"
  fi
}

for dockerfile in internal/image/fixtures/*.Dockerfile; do
  image_name=$(basename "$dockerfile" .Dockerfile)

  build_docker_image_fixture "$image_name"
done
