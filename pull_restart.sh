#!/bin/bash
cd /home/isucon/torb
git pull
cd /home/isucon/torb/webapp/ruby/
bundle install && sudo systemctl stop torb.ruby && sudo systemctl start torb.ruby
sleep(2)
sudo systemctl status torb.ruby
