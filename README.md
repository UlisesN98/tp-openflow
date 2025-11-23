# tp-openflow
En una terminal, dentro de pox/, correr el controlador POX:
``` bash
./pox.py misc.controller
```

En otra terminal, levantar topología (con 4 switches):
``` bash
sudo mn --custom topology.py --topo customTopo,num_switches=4 --controller remote --switch ovsk --mac --arp
```

En Mininet:
``` bash
mininet> pingall
```