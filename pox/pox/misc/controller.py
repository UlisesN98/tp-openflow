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

FIREWALL_SWITCH = "00-00-00-00-00-02"

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

        if dpid_str != FIREWALL_SWITCH:
            log.info("Instalando comportamiento NORMAL en switch %s", dpid_str)
            fm = of.ofp_flow_mod()
            fm.priority = 1
            fm.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
            event.connection.send(fm)
            return
        log.info("ConnectionUp Switch: %s", dpid_str)

        self.mac_to_port[dpid_str] = {}
    
    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid_str = dpidToStr(event.dpid)
    
        if dpid_str != FIREWALL_SWITCH:
            return

        in_port = event.port
        # Aprendo la MAC origen
        self.mac_to_port[dpid_str][packet.src] = in_port

        # Si sé dónde está la MAC destino → salida específica
        if packet.dst in self.mac_to_port[dpid_str]:
            out_port = self.mac_to_port[dpid_str][packet.dst]

            # Evito loops
            if out_port == in_port:
                log.warning("Dropping: src y dst en el mismo puerto (%s)", in_port)
                return

            # Instalo la regla en el switch
            fm = of.ofp_flow_mod()
            fm.match.dl_dst = packet.dst
            fm.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(fm)

            # Y además envío este paquete pendiente
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_output(port=out_port))
            msg.in_port = in_port
            event.connection.send(msg)

            log.info("Aprendido %s → %s en %s (regla instalada)",
                     packet.dst, out_port, dpid_str)

        else:
            # No conozco destino → flooding
            out_port = of.OFPP_FLOOD

            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_output(port=out_port))
            msg.in_port = in_port
            event.connection.send(msg)

            log.info("Flooding en %s para %s", dpid_str, packet.dst)

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