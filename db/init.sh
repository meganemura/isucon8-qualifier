#!/bin/bash

mysql="mysql -h 172.17.63.3"
if [ `whoami` != "isucon" ]; then
  mysql="mysql -h 127.0.0.1"
fi

ROOT_DIR=$(cd $(dirname $0)/..; pwd)
DB_DIR="$ROOT_DIR/db"
BENCH_DIR="$ROOT_DIR/bench"

export MYSQL_PWD=isucon

$mysql -uisucon -e "DROP DATABASE IF EXISTS torb; CREATE DATABASE torb;"
$mysql -uisucon torb < "$DB_DIR/schema.sql"

if [ ! -f "$DB_DIR/isucon8q-initial-dataset.sql.gz" ]; then
  echo "Run the following command beforehand." 1>&2
  echo "$ ( cd \"$BENCH_DIR\" && bin/gen-initial-dataset )" 1>&2
  exit 1
fi

$mysql -uisucon torb -e 'ALTER TABLE reservations DROP KEY event_id_and_sheet_id_idx'
gzip -dc "$DB_DIR/isucon8q-initial-dataset.sql.gz" | $mysql -uisucon torb
$mysql -uisucon torb -e 'ALTER TABLE reservations ADD KEY event_id_and_sheet_id_idx (event_id, sheet_id)'

$mysql -uisucon torb -e 'update reservations.sheet_rank, reservations.sheet_num, reservations.sheet_price, `sheets.rank`  set reservations.sheet_rank = `sheets.rank`, reservations.sheet_price = sheets.price, reservations.sheet_num = sheets.num  where reservations.sheet_id = sheets.id'
$mysql -uisucon torb -e 'update reservations.event_price, `event.price`  set reservations.event_price = `events.price` where reservations.event_id = events.id'
