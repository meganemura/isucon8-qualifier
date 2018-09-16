#!/bin/bash
cd /home/isucon/torb
git pull && sudo systemctl stop torb.ruby && sudo systemctl start torb.ruby
