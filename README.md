# tp-openflow
## Correrlo
En una terminal, dentro de pox/, correr el controlador `POX`:
``` bash
./pox.py misc.controller
```

En otra terminal, levantar topología (con 4 switches):
``` bash
sudo mn --custom topology.py --topo customTopo,num_switches=4 --controller remote --switch ovsk --mac --arp
```

En `mininet`:
``` mininet 
mininet> pingall
```
## Funcionalidades
Para probar funcionalidad con `iperf`, abro las terminales de los host que quiera:
``` mininet 
mininet> xterm h1 h2 ... hN
```
Luego en cada terminal `xterm` puedo correr el `iperf` como:
* Servidor con puerto **TCP**:
    ``` xterm
    $ iperf -c <IP-Servidor> -p <Puerto-Servidor>
    ```
* Servidor con puerto **UDP**:
    ``` xterm
    $ iperf -c <IP-Servidor> -p <Puerto-Servidor> -u
    ```
* O cliente con puerto **TCP**:
    ``` xterm
    $ iperf -s -p <Puerto-Servidor> 
    ```
* Cliente con puerto **UDP**:
    ``` xterm
    $ iperf -s -p <Puerto-Servidor> -u
    ```