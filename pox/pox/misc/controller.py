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
                raw_rules = json.load(f)
                log.info("Loaded rules from %s", RULES_PATH)
                
                expanded_rules = []
                for rule in raw_rules:
                    protocol = rule.get("protocol", "").upper()
                    has_port = "dst_port" in rule or "src_port" in rule
                    
                    # Expandir por protocolo (si es ANY con puerto)
                    if protocol == "ANY" and has_port:
                        # Expandir a TCP y UDP
                        for p in ["TCP", "UDP", "SCTP"]:
                            r2 = dict(rule)
                            r2["protocol"] = p
                            r2["ip_version"] = "IPv4"
                            
                            # Actualizar nombre para distinguir
                            if "name" in r2:
                                r2["name"] = f"{r2['name']} ({p})"
                            
                            expanded_rules.append(r2)
                    else:
                        # Regla normal (no expandir)
                        r2 = dict(rule)
                        
                        # Agregar IPv4 si usa protocolos L3/L4
                        if protocol in ["TCP", "UDP", "ICMP", "SCTP"] or has_port or "src_ip" in rule or "dst_ip" in rule:
                            r2["ip_version"] = "IPv4"
                        
                        expanded_rules.append(r2)
                
                log.info("Expanded %d rules to %d rules", len(raw_rules), len(expanded_rules))
                return expanded_rules
        else:
            log.error("Rules file %s not found", RULES_PATH)
            return []

    def install_rule(self, rule, connection):
        protocol = rule.get("protocol", "").upper()
        ip_version = rule.get("ip_version")  # ← Quitar default

        # Construí el flow_mod
        fm = of.ofp_flow_mod()
        fm.priority = rule.get("priority", PRIO_FIREWALL)
        fm.match = of.ofp_match()

        # Protocol (si se especifica)
        if protocol == "TCP":
            fm.match.dl_type = 0x0800
            fm.match.nw_proto = 6
        elif protocol == "UDP":
            fm.match.dl_type = 0x0800
            fm.match.nw_proto = 17
        elif protocol == "SCTP":  # ← AGREGAR ESTO
            fm.match.dl_type = 0x0800
            fm.match.nw_proto = 132
        elif protocol == "ICMP":
            fm.match.dl_type = 0x0800
            fm.match.nw_proto = 1   # ICMPv4

        # CAPA 2
        if "src_mac" in rule:
            fm.match.dl_src = EthAddr(rule["src_mac"])
        if "dst_mac" in rule:
            fm.match.dl_dst = EthAddr(rule["dst_mac"])

        # CAPA 3 (IP)
        if "src_ip" in rule:
            fm.match.dl_type = 0x0800
            fm.match.nw_src = IPAddr(rule["src_ip"])
            if 'mask_src' in rule:
                mask = int(rule['mask_src'])
                fm.match.nw_src = (IPAddr(rule["src_ip"]), mask)
        
        if "dst_ip" in rule:
            fm.match.dl_type = 0x0800
            fm.match.nw_dst = IPAddr(rule["dst_ip"])
            if 'mask_dst' in rule:
                mask = int(rule['mask_dst'])
                fm.match.nw_dst = (IPAddr(rule["dst_ip"]), mask)

        # PUERTOS (requieren nw_proto definido previamente)
        if "src_port" in rule or "dst_port" in rule:
            if fm.match.nw_proto is None:
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
        """
        Retorna un diccionario en formato de regla con los campos que matchearon,
        o None si el paquete no está bloqueado.
        """
        eth_src = str(packet.src)
        eth_dst = str(packet.dst)
        ip = packet.find('ipv4')
        udp = packet.find('udp')
        tcp = packet.find('tcp')
        icmp = packet.find('icmp')
        sctp = packet.find('sctp')

        for rule in self.rules:
            matched_rule = {}  # Formato de regla directamente
            
            # Verificar reglas de capa 2
            if 'src_mac' in rule:
                if eth_src != rule['src_mac']:
                    continue
                matched_rule['src_mac'] = eth_src
                
            if 'dst_mac' in rule:
                if eth_dst != rule['dst_mac']:
                    continue
                matched_rule['dst_mac'] = eth_dst

            # Verificar reglas L3/L4
            protocol = rule.get('protocol', '').upper()
            
            # Si la regla requiere IP pero el paquete no es IP -> no matchea
            if ('src_ip' in rule or 'dst_ip' in rule or protocol in ['TCP', 'UDP', 'ICMP', 'SCTP']) and ip is None:
                continue
            
            if ip is not None:
                matched_rule['ip_version'] = 'IPv4'
                
                # Verificar src_ip
                if 'src_ip' in rule:
                    if str(ip.srcip) != rule['src_ip']:
                        continue
                    matched_rule['src_ip'] = str(ip.srcip)
                    if 'mask_src' in rule:
                        matched_rule['mask_src'] = rule['mask_src']
                
                # Verificar dst_ip
                if 'dst_ip' in rule:
                    if str(ip.dstip) != rule['dst_ip']:
                        continue
                    matched_rule['dst_ip'] = str(ip.dstip)
                    if 'mask_dst' in rule:
                        matched_rule['mask_dst'] = rule['mask_dst']

                # Verificar protocolo y puerto
                if protocol == 'TCP':
                    if tcp is None:
                        continue
                    matched_rule['protocol'] = 'TCP'
                    
                    if 'src_port' in rule:
                        if tcp.srcport != int(rule['src_port']):
                            continue
                        matched_rule['src_port'] = tcp.srcport
                        
                    if 'dst_port' in rule:
                        if tcp.dstport != int(rule['dst_port']):
                            continue
                        matched_rule['dst_port'] = tcp.dstport
                        
                elif protocol == 'UDP':
                    if udp is None:
                        continue
                    matched_rule['protocol'] = 'UDP'
                    
                    if 'src_port' in rule:
                        if udp.srcport != int(rule['src_port']):
                            continue
                        matched_rule['src_port'] = udp.srcport
                        
                    if 'dst_port' in rule:
                        if udp.dstport != int(rule['dst_port']):
                            continue
                        matched_rule['dst_port'] = udp.dstport
                        
                elif protocol == 'SCTP':  # ← AGREGAR ESTO
                    if sctp is None:
                        continue
                    matched_rule['protocol'] = 'SCTP'
                    
                    if 'src_port' in rule:
                        if sctp.srcport != int(rule['src_port']):
                            continue
                        matched_rule['src_port'] = sctp.srcport
                        
                    if 'dst_port' in rule:
                        if sctp.dstport != int(rule['dst_port']):
                            continue
                        matched_rule['dst_port'] = sctp.dstport
                    
                elif protocol == 'ICMP':
                    if icmp is None:  # ← AGREGAR ESTA VERIFICACIÓN
                        continue
                    matched_rule['protocol'] = 'ICMP'
            
            # Si llegamos aquí, todos los campos matchearon
            if matched_rule:
                matched_rule['name'] = f"Dynamic DROP from rule: {rule.get('name', '<no-name>')}"
                matched_rule['priority'] = PRIO_FIREWALL
                log.debug("Packet blocked by rule: %s", rule.get("name", "<no-name>"))
                return matched_rule
        
        return None

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

            blocked_rule = self.packet_blocked_by_rule(packet)

            if blocked_rule:
                log.info("Packet matches firewall rule — installing explicit DROP")
                # Directamente usar install_rule()!
                self.install_rule(blocked_rule, event.connection)
                # NO enviar el paquete (drop)
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
