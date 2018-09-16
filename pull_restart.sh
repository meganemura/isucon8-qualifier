#!/bin/bash
cd /home/isucon/torb
git pull && bundle install && sudo systemctl stop torb.ruby && sudo systemctl start torb.ruby
sudo systemctl status torb.ruby
