# TP N◦2: Software-Defined Networks

## Ejecución
### Ejecutar Pox
En una terminal, dentro del directorio pox/, correr el controlador `POX`:
``` bash
./pox.py misc.controller
```

### Ejecutar Mininet
En otra terminal levantar la topología, especificando la cantidad de switches deseados:
``` bash
sudo mn --custom topology.py --topo customTopo,num_switches=<Num-Switches> --controller remote --switch ovsk --mac --arp
```

## Funcionalidades

### Pruebas de conectividad
Desde la consola de `mininet`:
``` mininet 
mininet> pingall
```

### Pruebas con iperf
Para probar funcionalidad con `iperf`, abro las terminales de los host que quiera:
``` mininet 
mininet> xterm h1 h2 ... hN
```
Luego en cada terminal `xterm` puedo correr el `iperf` como:
* Servidor con puerto **TCP**:
    ``` xterm
    $ iperf -s -p <Puerto-Servidor>
    ```
* Servidor con puerto **UDP**:
    ``` xterm
    $ iperf -s -u -p <Puerto-Servidor>
    ```
* O cliente con puerto **TCP**:
    ``` xterm
    $ iperf -c <IP-Servidor> -p <Puerto-Servidor>
    ```
* Cliente con puerto **UDP**:
    ``` xterm
    $ iperf -c <IP-Servidor> -u -p <Puerto-Servidor>
    ```

## Ejecución de los scripts de prueba
Asegurarse de que tengan permisos de ejecución:
```
chmod +x tests/test_ping.sh tests/test_iperf.sh
```
Correr las pruebas:
```
./tests/test_ping.sh
./tests/test_iperf.sh
```