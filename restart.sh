#!/bin/bash
sudo systemctl stop torb.ruby && sudo systemctl start torb.ruby
sudo systemctl status torb.ruby
