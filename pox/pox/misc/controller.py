from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
import os
import json

log = core.getLogger()

RULES_PATH = "pox/misc/rules.json"

class Controller(EventMixin):
    def __init__(self):
        log.info("Controller Init")
        self.listenTo(core.openflow)
        self.rules = self.get_rules()
        log.debug("Enabling Firewall Module")
        
    def _handle_ConnectionUp(self, event):
        dpid = event.dpid
        dpid_str = dpidToStr(dpid)
        log.info("ConnectionUp Switch: %s", dpid_str)
        
        self.install_firewall_rules(event)

    def get_rules(self):
        if os.path.exists(RULES_PATH):
            with open(RULES_PATH) as f:
                log.info("Loaded rules from %s", RULES_PATH)
                return json.load(f)
        else:
            log.error("Rules file %s not found", RULES_PATH)
            return []
    
    def install_firewall_rules(self, event):
        if not self.rules:
            log.debug("No firewall rules to install")
            return
        
        dpid_str = dpidToStr(event.dpid)
        rules_installed = 0
        
        for rule in self.rules:
            try:
                self.install_blocking_rule(event, rule)
                rules_installed += 1
            except Exception as e:
                log.error("Error installing rule %s: %s", rule.get('name', 'unnamed'), e)
        
        log.info("Installed %d firewall rules on switch %s", rules_installed, dpid_str)
    
    def install_blocking_rule(self, event, rule):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = 0x0800  # IPv4
        msg.priority = 100
        
        if 'protocol' in rule:
            protocol = rule['protocol'].upper()
            if protocol == 'TCP':
                msg.match.nw_proto = 6
            elif protocol == 'UDP':
                msg.match.nw_proto = 17
        
        if 'dst_port' in rule:
            msg.match.tp_dst = rule['dst_port']
        
        if 'src_ip' in rule:
            msg.match.nw_src = rule['src_ip']
        
        if 'dst_ip' in rule:
            msg.match.nw_dst = rule['dst_ip']
        
        if 'src_mac' in rule:
            msg.match.dl_src = EthAddr(rule['src_mac'])
        
        if 'dst_mac' in rule:
            msg.match.dl_dst = EthAddr(rule['dst_mac'])
        
        # Sin acciones = descartar paquete (comportamiento por defecto OpenFlow)
        
        event.connection.send(msg)
        rule_name = rule.get('name', 'unnamed')
        log.debug("Installed blocking rule '%s' on switch %s", rule_name, dpidToStr(event.dpid))

def launch():
    log.info("Controller Launch")
    core.registerNew(Controller)