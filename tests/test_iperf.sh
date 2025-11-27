# #!/bin/bash

pkill -f pox.py 2>/dev/null

echo "Starting POX controller"
(
    cd pox
    ./pox.py misc.controller > /dev/null 2>&1 &
)
sleep 3
sudo python3 tests/test_runner.py

sudo mn -c > /dev/null 2>&1
pkill -f pox.py > /dev/null 2>&1

echo "Iperf tests completed!"