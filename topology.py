from mininet.topo import Topo

class CustomTopo(Topo):
    def __init__(self, num_switches):
        if not isinstance(num_switches, int):
            raise TypeError(
                f"El número de switches debe ser un entero, recibido: {type(num_switches).__name__}"
            )
        
        if num_switches < 2:
            raise ValueError(
                f"La topología requiere al menos 2 switches para funcionar correctamente.\n"
                f"Razones:\n"
                f"  - Se necesita un switch para hosts h1 y h2 (s1)\n"
                f"  - Se necesita otro switch para hosts h3 y h4 (s{num_switches})\n"
                f"  - El firewall está configurado para operar en s2 (DPID 00-00-00-00-00-02)\n"
                f"Número de switches recibido: {num_switches}\n"
                f"Por favor, especifique num_switches >= 2"
            )
        
        # Initialize topology
        Topo.__init__(self)

        # Create switches
        switches = []
        for i in range(num_switches):
            s = self.addSwitch(f's{i+1}')
            switches.append(s)
                               
        # Create hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Add links between switches and hosts
        self.addLink(switches[0], h1)
        self.addLink(switches[0], h2)
        self.addLink(switches[-1], h3)
        self.addLink(switches[-1], h4)

        # Add links between switches
        for i in range(len(switches) - 1):
            self.addLink(switches[i], switches[i + 1])

topos = { 'customTopo': CustomTopo }