#!/bin/bash

pkill -f pox.py 2>/dev/null

echo "Starting POX controller"
(
    cd pox
    ./pox.py misc.controller > /dev/null 2>&1 &
)
sleep 3

echo "Starting Mininet"
sudo mn \
    --custom topology.py \
    --topo customTopo,num_switches=4 \
    --controller remote \
    --switch ovsk \
    --mac --arp << 'EOF'

py time.sleep(3)
pingall

EOF

sudo mn -c > /dev/null 2>&1
pkill -f pox.py > /dev/null 2>&1

echo "Ping test completed!"
