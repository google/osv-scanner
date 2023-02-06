#!/usr/bin/env bash
# Inspired by: https://raw.githubusercontent.com/anchore/grype/main/test/integration/test-fixtures/image-centos-match-coverage/var/lib/rpm/generate-fixture.sh
set -eux

docker create --name gen-rpmdb-bdb centos:8 sh -c 'tail -f /dev/null'

function cleanup {
  docker kill gen-rpmdb-bdb
  docker rm gen-rpmdb-bdb
}
trap cleanup EXIT

docker start gen-rpmdb-bdb
docker exec -i --tty=false gen-rpmdb-bdb bash <<-EOF
  mkdir /rpmdb
  cd /rpmdb
  rpm --initdb --dbpath /rpmdb
  curl -sSLO https://rpmfind.net/linux/epel/8/Everything/x86_64/Packages/h/htop-3.2.1-1.el8.x86_64.rpm
  rpm --dbpath /rpmdb -ivh htop-3.2.1-1.el8.x86_64.rpm
  rm -f htop-3.2.1-1.el8.x86_64.rpm
  rpm --dbpath /rpmdb -qa
EOF

docker cp gen-rpmdb-bdb:/rpmdb/Packages .
