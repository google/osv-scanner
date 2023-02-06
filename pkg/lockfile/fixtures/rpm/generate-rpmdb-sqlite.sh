#!/usr/bin/env bash
# Inspired by: https://raw.githubusercontent.com/anchore/grype/main/test/integration/test-fixtures/image-centos-match-coverage/var/lib/rpm/generate-fixture.sh
set -eux

docker create --name gen-rpmdb-sqlite rockylinux:9 sh -c 'tail -f /dev/null'

function cleanup {
  docker kill gen-rpmdb-sqlite
  docker rm gen-rpmdb-sqlite
}
trap cleanup EXIT

docker start gen-rpmdb-sqlite
docker exec -i --tty=false gen-rpmdb-sqlite bash <<-EOF
  mkdir /rpmdb
  cd /rpmdb
  rpm --initdb --dbpath /rpmdb
  curl -sSLO https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/Packages/h/htop-3.2.1-1.el9.x86_64.rpm
  rpm --dbpath /rpmdb -ivh htop-3.2.1-1.el9.x86_64.rpm
  rm -f htop-3.2.1-1.el9.x86_64.rpm
  rpm --dbpath /rpmdb -qa
EOF

docker cp gen-rpmdb-sqlite:/rpmdb/rpmdb.sqlite .
