from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
import json

log = core.getLogger()

RULES_PATH = "pox/misc/rules.json"

class Controller(EventMixin):
    def __init__(self):
        log.info("Controller Init")
        self.listenTo(core.openflow)
        self.rules = self.get_rules()
        log.debug("Enabling␣Firewall␣Module")
        self.mac_to_port = {}
        
    def _handle_ConnectionUp(self, event):
        dpid = event.dpid
        dpid_str = dpidToStr(dpid)
        log.info("ConnectionUp Switch: %s", dpid_str)

        self.mac_to_port[dpid_str] = {}
    
    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid_str = dpidToStr(event.dpid)
        log.info("PacketIn: %s", dpid_str)

        in_port = event.port
        self.mac_to_port[dpid_str][packet.src] = in_port

        if packet.dst in self.mac_to_port[dpid_str]:
            out_port = self.mac_to_port[dpid_str][packet.dst]
        else:
            out_port = of.OFPP_FLOOD
        
        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

    def get_rules(self):
        if os.path.exists(RULES_PATH):
            with open(RULES_PATH) as f:
                log.info("Loaded rules from %s", RULES_PATH)
                return json.load(f)
        else:
            log.error("Rules file %s not found", RULES_PATH)
            return []

def launch():
    log.info("Controller Launch")
    core.registerNew(Controller)