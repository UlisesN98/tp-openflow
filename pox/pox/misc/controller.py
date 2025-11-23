from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
import os, json

log = core.getLogger()

RULES_PATH = "pox/misc/rules.json"
FIREWALL_SWITCH = "00-00-00-00-00-02"

PRIO_FIREWALL = 10000   # reglas de bloqueo proactivas
PRIO_LEARN = 100        # reglas de forwarding aprendidas (baja)

class Controller(EventMixin):
    def __init__(self):
        log.info("Controller Init")
        self.listenTo(core.openflow)
        self.rules = self.get_rules()
        log.debug("Firewall module enabled")
        self.mac_to_port = {}

    def get_rules(self):
        if os.path.exists(RULES_PATH):
            with open(RULES_PATH) as f:
                log.info("Loaded rules from %s", RULES_PATH)
                return json.load(f)
        else:
            log.error("Rules file %s not found", RULES_PATH)
            return []

    def install_rule(self, rule, connection):
        proto = rule.get("protocol", "").upper()

        # Si ANY y puerto -> desdoblamos en TCP y UDP
        if proto == "ANY" and ("dst_port" in rule or "src_port" in rule):
            for p in ["TCP", "UDP"]:
                r2 = dict(rule)
                r2["protocol"] = p
                self.install_rule(r2, connection)
            return

        # Construí el flow_mod
        fm = of.ofp_flow_mod()
        fm.priority = rule.get("priority", PRIO_FIREWALL)
        fm.match = of.ofp_match()

        # Protocol (si se especifica)
        if proto == "TCP":
            fm.match.dl_type = 0x0800
            fm.match.nw_proto = 6
        elif proto == "UDP":
            fm.match.dl_type = 0x0800
            fm.match.nw_proto = 17
        elif proto == "ICMP":
            fm.match.dl_type = 0x0800
            fm.match.nw_proto = 1

        # CAPA 2
        if "src_mac" in rule:
            fm.match.dl_src = EthAddr(rule["src_mac"])
        if "dst_mac" in rule:
            fm.match.dl_dst = EthAddr(rule["dst_mac"])

        # CAPA 3 (IP)
        if "src_ip" in rule:
            fm.match.dl_type = 0x0800
            fm.match.nw_src = IPAddr(rule["src_ip"])
        if "dst_ip" in rule:
            fm.match.dl_type = 0x0800
            fm.match.nw_dst = IPAddr(rule["dst_ip"])

        # PUERTOS (requieren nw_proto definido previamente)
        if "src_port" in rule or "dst_port" in rule:
            if not hasattr(fm.match, "nw_proto"):
                log.warning("Regla %s ignorada: puerto sin protocolo transport", rule.get("name","<no-name>"))
                return
            if "src_port" in rule:
                fm.match.tp_src = int(rule["src_port"])
            if "dst_port" in rule:
                fm.match.tp_dst = int(rule["dst_port"])

        # Sin acciones -> DROP
        fm.actions = []
        connection.send(fm)
        log.info("Firewall rule installed: %s (priority=%d)", rule.get("name","<no-name>"), fm.priority)

    def packet_blocked_by_rule(self, packet):
        # Pre-extraer info del paquete (puede ser None si no existe)
        eth_src = str(packet.src)
        eth_dst = str(packet.dst)
        ip = packet.find('ipv4')
        udp = packet.find('udp')
        tcp = packet.find('tcp')

        for rule in self.rules:
            # Si la regla especifica src_mac/dst_mac y ambas coinciden -> bloquear
            if 'src_mac' in rule and 'dst_mac' in rule:
                if eth_src == rule['src_mac'] and eth_dst == rule['dst_mac']:
                    return True

            # Si la regla es L3/L4 y el paquete es IPv4, comparar
            if ip is not None:
                # src_ip/dst_ip si están
                if 'src_ip' in rule and str(ip.srcip) != rule['src_ip']:
                    continue
                if 'dst_ip' in rule and str(ip.dstip) != rule['dst_ip']:
                    continue

                # protocolo/puerto
                proto = rule.get('protocol', '').upper()
                if proto == 'ANY':
                    # si dst_port especificado, requiere que exista tcp/udp y puerto coincida
                    if 'dst_port' in rule:
                        if udp and udp.dstport == int(rule['dst_port']):
                            return True
                        if tcp and tcp.dstport == int(rule['dst_port']):
                            return True
                        # no coincidio => continue to next rule
                        continue
                    else:
                        # ANY sin puerto + IP coincidió => bloquear
                        return True
                elif proto == 'TCP' and tcp is not None:
                    if 'dst_port' in rule and tcp.dstport != int(rule['dst_port']):
                        continue
                    return True
                elif proto == 'UDP' and udp is not None:
                    if 'dst_port' in rule and udp.dstport != int(rule['dst_port']):
                        continue
                    return True
                # si la regla quiere TCP pero el paquete no es TCP -> no coincide
            else:
                # paquete no-ip: aún así podemos bloquear por MAC si regla lo especifica
                # las reglas L3 no aplican a paquetes no-ip (como ARP)
                pass

        return False

    def _handle_ConnectionUp(self, event):
        dpid = event.dpid
        dpid_str = dpidToStr(dpid)
        log.info("ConnectionUp %s", dpid_str)

        # switches que no son firewall -> NORMAL behavior
        if dpid_str != FIREWALL_SWITCH:
            log.info("Configuring switch %s as NORMAL pipeline", dpid_str)
            fm = of.ofp_flow_mod()
            fm.priority = 1
            fm.match = of.ofp_match()
            fm.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
            event.connection.send(fm)
            return

        # Para s2 inicializamos tabla y instalamos reglas proactivas
        self.mac_to_port[dpid_str] = {}
        log.info("Installing firewall rules proactively on %s", dpid_str)

        # instalamos todas las reglas del JSON proactivamente
        for rule in self.rules:
            self.install_rule(rule, event.connection)

        log.info("Firewall rules installed on %s", dpid_str)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            return

        dpid_str = dpidToStr(event.dpid)
        if dpid_str != FIREWALL_SWITCH:
            return

        in_port = event.port
        # Aprendo la MAC origen
        self.mac_to_port.setdefault(dpid_str, {})
        self.mac_to_port[dpid_str][packet.src] = in_port

        # Si sé dónde está la MAC destino → salida específica
        if packet.dst in self.mac_to_port[dpid_str]:
            out_port = self.mac_to_port[dpid_str][packet.dst]

            # Evito loops
            if out_port == in_port:
                log.warning("Dropping: src y dst en el mismo puerto (%s)", in_port)
                return

            # Si el paquete sería bloqueado por alguna regla, NO instalamos flow
            if self.packet_blocked_by_rule(packet):
                log.info("Packet matches firewall rule — not installing learned flow for %s -> %s",
                         packet.src, packet.dst)
                return

            # Instalamos UN flow específico por par src+dst con prioridad baja
            fm = of.ofp_flow_mod()
            fm.priority = PRIO_LEARN
            fm.match = of.ofp_match()
            fm.match.dl_src = packet.src
            fm.match.dl_dst = packet.dst
            fm.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(fm)

            # Enviamos el paquete pendiente una sola vez
            msg = of.ofp_packet_out()
            msg.data = event.ofp.data
            msg.in_port = in_port
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)

            log.info("Learned flow installed: %s -> %s via port %s", packet.src, packet.dst, out_port)

        else:
            # No conocemos destino -> flooding (solo para este paquete)
            msg = of.ofp_packet_out()
            msg.data = event.ofp.data
            msg.in_port = in_port
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)
            log.info("Flooding packet on %s for %s", dpid_str, packet.dst)

def launch():
    log.info("Controller Launch")
    core.registerNew(Controller)
