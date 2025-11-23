from mininet.topo import Topo

class CustomTopo(Topo):
    def __init__(self, num_switches):
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