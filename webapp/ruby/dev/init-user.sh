#!/bin/bash

cat <<'EOF' | mysql -uroot -h 127.0.0.1
CREATE USER IF NOT EXISTS 'isucon'@'%' IDENTIFIED BY 'isucon';
GRANT ALL ON torb.* TO 'isucon'@'%';
CREATE USER IF NOT EXISTS 'isucon'@'localhost' IDENTIFIED BY 'isucon';
GRANT ALL ON torb.* TO 'isucon'@'localhost';
EOF
