#!/bin/bash -ex

docker-compose up -d

sleep 5

bundle install --jobs 12

dev/init-user.sh
../../db/init.sh

# ../env.sh から
export DB_DATABASE=torb
export DB_HOST=127.0.0.1
export DB_PORT=3306
export DB_USER=isucon
export DB_PASS=isucon

bundle exec rackup
