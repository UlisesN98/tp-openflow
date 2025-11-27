import sys
import os
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.node import RemoteController, OVSSwitch
from time import sleep

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from topology import CustomTopo


def start_net():
    net = Mininet(
        topo=CustomTopo(num_switches=4),
        controller=lambda name: RemoteController(name, ip='127.0.0.1'),
        switch=OVSSwitch,
        autoSetMacs=True,
        autoStaticArp=True
    )
    net.start()
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
    return net, h1, h2, h3, h4


def test_rule_1_tcp_block(h1, h2, h3, h4):
    print("\n -------- Rule 1: Block port 80 -------- ")

    print("Starting TCP server on h1 port 80")
    h1.cmd("iperf -s -p 80 &")
    sleep(1)

    print("Test TCP port 80 must be blocked (h4 -> h1)")
    print(h4.cmd("timeout 3 iperf -u -c 10.0.0.1 -p 80 &"))
    sleep(5)

    print("Test TCP port 80 with h2 allowed (h2 -> h1)")
    print(h2.cmd("iperf -c 10.0.0.1 -p 80"))
    h1.cmd("^C") 
    h2.cmd("^C") 
    h3.cmd("^C")
    h4.cmd("^C")


def test_rule_1_udp_block(h1, h2, h3, h4):
    print("Starting UDP server on h1 port 80")
    h1.cmd("iperf -s -u -p 80 &")
    sleep(1)

    print("Test UDP port 80 must be blocked (h4 -> h1)")
    print(h4.cmd("timeout 3 iperf -u -c 10.0.0.1 -p 80"))

    print("Test TCP port 80 with h2 allowed (h2 -> h1)")
    print(h2.cmd("iperf -c 10.0.0.1 -u -p 80"))
    h1.cmd("^C"), h2.cmd("^C"), h3.cmd("^C"), h4.cmd("^C")



def test_rule_2_udp_block(h1, h2, h3, h4):
    print("\n-------- Rule 2: Host_1 with UDP and port 5001 must be blocked --------")

    print("Starting UDP server on h4 port 5001")
    h4.cmd("iperf -s -u -p 5001 &")
    sleep(1)

    print("Test h1 -> h4 with UDP/5001 must be blocked")
    print(h1.cmd("timeout 3 iperf -u -c 10.0.0.4 -p 5001 -t 3"))
    h1.cmd("^C"), h2.cmd("^C"), h3.cmd("^C"), h4.cmd("^C")



def test_rule_2_tcp_allowed(h1, h2, h3, h4):
    print("Test h1 -> h4 with TCP/5001 allowed")
    h4.cmd("iperf -s -p 5001 &")
    sleep(1)
    print(h1.cmd("iperf -c 10.0.0.4 -p 5001 -t 3"))
    h1.cmd("^C"), h2.cmd("^C"), h3.cmd("^C"), h4.cmd("^C")



def test_rule_3_block(h1, h2, h3, h4):
    print("\n-------- Rule 3: Host_1 -> Host_3 blocked --------")

    print("Test UDP h1 -> h3 blocked")
    h3.cmd("iperf -u -s -p 6000 &")
    sleep(1)
    print(h1.cmd("timeout 3 iperf -u -c 10.0.0.3 -p 6000 -t 3"))
    h1.cmd("^C"), h2.cmd("^C"), h3.cmd("^C"), h4.cmd("^C")



def test_rule_4_block(h1, h2, h3, h4):
    print("\n-------- Rule 4: Host_3 -> Host_1 blocked --------")

    print("Test UDP h3 -> h1 blocked")
    h1.cmd("iperf -u -s -p 7000 &")
    sleep(1)
    print(h3.cmd("timeout 3 iperf -u -c 10.0.0.1 -p 7000 -t 3"))
    h1.cmd("^C"), h2.cmd("^C"), h3.cmd("^C"), h4.cmd("^C")



def run_tests():
    net, h1, h2, h3, h4 = start_net()
    test_rule_1_tcp_block(h1, h2, h3, h4)
    test_rule_1_udp_block(h1, h2, h3, h4)
    test_rule_2_udp_block(h1, h2, h3, h4)
    test_rule_2_tcp_allowed(h1, h2, h3, h4)
    test_rule_3_block(h1, h2, h3, h4)
    test_rule_4_block(h1, h2, h3, h4)
    net.stop()


if __name__ == "__main__":
    setLogLevel('info')
    run_tests()
