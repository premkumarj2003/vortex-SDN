"""
VORTEX-SDN Enterprise Ryu OpenFlow 1.3 Controller Application
Manages datapath discovery, port statistics, flow rule installations,
real-time OpenFlow telemetry collection, loop-free full-mesh forwarding,
and dynamic host discovery.
"""

import logging
import json
import time
from datetime import datetime, timezone

try:
    # pyrefly: ignore [missing-import]
    from ryu.base import app_manager  # type: ignore
    # pyrefly: ignore [missing-import]
    from ryu.controller import ofp_event  # type: ignore
    # pyrefly: ignore [missing-import]
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls  # type: ignore
    # pyrefly: ignore [missing-import]
    from ryu.ofproto import ofproto_v1_3  # type: ignore
    # pyrefly: ignore [missing-import]
    from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp, arp  # type: ignore
    # pyrefly: ignore [missing-import]
    from ryu.lib import hub  # type: ignore
    # pyrefly: ignore [missing-import]
    from ryu.app.wsgi import ControllerBase, WSGIApplication, route  # type: ignore
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False
    app_manager = type('obj', (object,), {'RyuApp': object})
    CONFIG_DISPATCHER = None
    MAIN_DISPATCHER = None
    ofp_event = type('obj', (object,), {
        'EventOFPSwitchFeatures': None,
        'EventOFPPacketIn': None,
        'EventOFPFlowStatsReply': None,
        'EventOFPPortStatsReply': None,
        'EventOFPFlowRemoved': None
    })
    def set_ev_cls(*args, **kwargs):
        return lambda fn: fn


# Direct 1-hop mesh backbone links between the 4 switches:
# MESH_LINKS[src_dpid][dst_dpid] -> egress_port_on_src
# In the 4-switch full mesh with 6 links:
# s1: port 1->h1, port 2->s2, port 3->s3, port 4->s4
# s2: port 1->h3, port 2->s1, port 3->s4, port 4->s3
# s3: port 1->h2, port 2->s1, port 3->s4, port 4->s2
# s4: port 1->h4, port 2->s2, port 3->s3, port 4->s1
MESH_LINKS = {
    1: {2: 2, 3: 3, 4: 4},
    2: {1: 2, 4: 3, 3: 4},
    3: {1: 2, 4: 3, 2: 4},
    4: {2: 2, 3: 3, 1: 4},
}

# Access / edge port on every switch connecting to its local host
ACCESS_PORT = 1

# Default host attachments in the VORTEX-SDN 4-switch topology
DEFAULT_HOSTS = {
    "00:00:00:00:00:01": {"ip": "10.0.0.1", "dpid": 1, "port": 1, "name": "h1"},
    "00:00:00:00:00:02": {"ip": "10.0.0.2", "dpid": 3, "port": 1, "name": "h2"},
    "00:00:00:00:00:03": {"ip": "10.0.0.3", "dpid": 2, "port": 1, "name": "h3"},
    "00:00:00:00:00:04": {"ip": "10.0.0.4", "dpid": 4, "port": 1, "name": "h4"},
}


class VortexRyuController(app_manager.RyuApp):
    OFP_VERSIONS = [1.3] if not RYU_AVAILABLE else [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        if RYU_AVAILABLE:
            super(VortexRyuController, self).__init__(*args, **kwargs)
        self.datapaths = {} # dpid_int -> datapath & dpid_str -> datapath
        self.switches = {} # dpid_str -> {ports, name, status, last_seen}
        self.hosts = {} # mac -> host_info
        self.ip_to_mac = {} # ip -> mac
        self.mac_to_ip = {} # mac -> ip
        self.links = [] # [(src_dpid, src_port, dst_dpid, dst_port)]
        self.flow_stats = {} # dpid_str -> list of flows
        self.port_stats = {} # (dpid_str, port) -> stats
        self.mac_to_port = {} # dpid_str -> {mac -> port}
        self.installed_flow_times = {} # (dpid_int, eth_dst) -> timestamp
        self.is_running = True

        # Pre-seed default host mapping
        for mac, hinfo in DEFAULT_HOSTS.items():
            dpid_str = format(hinfo["dpid"], "016x")
            self.hosts[mac] = {
                "mac": mac,
                "ip": hinfo["ip"],
                "switch_dpid": dpid_str,
                "switch_id": hinfo["dpid"],
                "switch_port": hinfo["port"],
                "name": hinfo["name"],
                "last_seen": datetime.now(timezone.utc).isoformat()
            }
            self.ip_to_mac[hinfo["ip"]] = mac
            self.mac_to_ip[mac] = hinfo["ip"]

        # Start background polling thread if Ryu is active
        if RYU_AVAILABLE:
            self.monitor_thread = hub.spawn(self._stats_monitor_loop)

    def _stats_monitor_loop(self):
        """Periodically requests flow and port stats from all connected switches."""
        while self.is_running:
            for dp_id, dp in list(self.datapaths.items()):
                if isinstance(dp_id, int):
                    self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Flow stats request
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # Port stats request
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _should_install_flow(self, dpid_int, eth_dst):
        """
        Determines if a flow rule should be installed.
        Allows re-installation when a flow has expired, while debouncing rapid packet bursts.
        """
        now = time.time()
        last_installed = self.installed_flow_times.get((dpid_int, eth_dst), 0)
        if (now - last_installed) > 2.0:
            self.installed_flow_times[(dpid_int, eth_dst)] = now
            return True
        return False

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """Handles flow removal notification from switch to invalidate cached flow state."""
        msg = ev.msg
        datapath = msg.datapath
        dpid_int = datapath.id
        match = msg.match
        eth_dst = match.get('eth_dst') if hasattr(match, 'get') else getattr(match, 'eth_dst', None)
        if eth_dst:
            self.installed_flow_times.pop((dpid_int, eth_dst), None)
            self.logger.info(f"[VORTEX-SDN] Flow expired on s{dpid_int}: dst={eth_dst} (cache invalidated)")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handles switch feature reply, installs table-miss flow entry (send to controller)."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid_int = datapath.id
        dpid_str = format(datapath.id, "016x")
        self.datapaths[dpid_int] = datapath
        self.datapaths[dpid_str] = datapath
        self.switches[dpid_str] = {
            "dpid": dpid_str,
            "dpid_int": dpid_int,
            "name": f"s{dpid_int}",
            "status": "ONLINE",
            "connected_at": datetime.now(timezone.utc).isoformat(),
            "ports": []
        }

        # Install table-miss flow entry: Priority 0 -> Send to Controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"[VORTEX-SDN] Switch connected: DPID={dpid_str} (s{dpid_int})")

        # Proactively install flow rule for the switch's local host on Port 1
        for mac, hinfo in self.hosts.items():
            if hinfo.get("switch_id") == dpid_int:
                host_match = parser.OFPMatch(eth_dst=mac)
                host_actions = [parser.OFPActionOutput(hinfo["switch_port"])]
                self.add_flow(datapath, 100, host_match, host_actions, idle_timeout=0)
                self.logger.info(f"[VORTEX-SDN] Local host flow active on s{dpid_int}: dst={mac} -> port {hinfo['switch_port']}")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Installs OpenFlow 1.3 flow rule with flow removal notifications."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        flags = ofproto.OFPFF_SEND_FLOW_REM if idle_timeout > 0 else 0
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id, priority=priority,
                match=match, instructions=inst, flags=flags,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match,
                instructions=inst, flags=flags,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout
            )
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handles incoming packet-in messages with loop-free topology forwarding."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP
            return

        dst = eth.dst
        src = eth.src
        dpid_int = datapath.id
        dpid_str = format(dpid_int, "016x")

        # 1. Host Learning: Only learn host location from access ports (port 1)
        # to avoid MAC flapping caused by transit traffic across mesh links.
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_src = ip_pkt.src if ip_pkt else (arp_pkt.src_ip if arp_pkt else None)

        if in_port == ACCESS_PORT:
            if src not in self.hosts:
                self.logger.info(f"[VORTEX-SDN] Discovered host MAC={src} IP={ip_src} at s{dpid_int}:port {in_port}")
            self.hosts[src] = {
                "mac": src,
                "ip": ip_src or self.hosts.get(src, {}).get("ip"),
                "switch_dpid": dpid_str,
                "switch_id": dpid_int,
                "switch_port": in_port,
                "last_seen": datetime.now(timezone.utc).isoformat()
            }
            if ip_src:
                self.ip_to_mac[ip_src] = src
                self.mac_to_ip[src] = ip_src

        # 2. ARP Handling & Broadcast Loop Prevention
        is_broadcast = (dst == "ff:ff:ff:ff:ff:ff" or dst.startswith("33:33:") or dst.startswith("01:00:5e:"))

        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            target_ip = arp_pkt.dst_ip
            target_mac = self.ip_to_mac.get(target_ip)
            # If target host MAC is known, reply directly with Proxy ARP
            if target_mac:
                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(ethernet.ethernet(
                    ethertype=ether_types.ETH_TYPE_ARP,
                    dst=src,
                    src=target_mac
                ))
                reply_pkt.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=target_mac,
                    src_ip=target_ip,
                    dst_mac=src,
                    dst_ip=arp_pkt.src_ip
                ))
                reply_pkt.serialize()
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=[parser.OFPActionOutput(in_port)],
                    data=reply_pkt.data
                )
                datapath.send_msg(out)
                return

        if is_broadcast:
            # BROADCAST LOOP PREVENTION:
            # Deliver broadcast packets ONLY out of the access port (Port 1)
            # of all other switches. NEVER flood to mesh backbone ports (2, 3, 4).
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            for dp_id, dp in self.datapaths.items():
                if isinstance(dp_id, int) and dp_id != dpid_int:
                    out = dp.ofproto_parser.OFPPacketOut(
                        datapath=dp,
                        buffer_id=dp.ofproto.OFP_NO_BUFFER,
                        in_port=dp.ofproto.OFPP_CONTROLLER,
                        actions=[dp.ofproto_parser.OFPActionOutput(ACCESS_PORT)],
                        data=msg.data
                    )
                    dp.send_msg(out)
            return

        # 3. Unicast Forwarding & End-to-End Flow Installation
        dst_host = self.hosts.get(dst)
        if not dst_host:
            # Unrecognized destination unicast: output only to host access ports
            for dp_id, dp in self.datapaths.items():
                if isinstance(dp_id, int) and dp_id != dpid_int:
                    out = dp.ofproto_parser.OFPPacketOut(
                        datapath=dp,
                        buffer_id=dp.ofproto.OFP_NO_BUFFER,
                        in_port=dp.ofproto.OFPP_CONTROLLER,
                        actions=[dp.ofproto_parser.OFPActionOutput(ACCESS_PORT)],
                        data=msg.data
                    )
                    dp.send_msg(out)
            return

        dst_dpid = dst_host["switch_id"]
        dst_port = dst_host["switch_port"]

        if dpid_int == dst_dpid:
            # Destination host is local to this switch
            out_port = dst_port
        else:
            # Destination host is on another switch: use direct mesh link
            out_port = MESH_LINKS.get(dpid_int, {}).get(dst_dpid)
            if out_port is None:
                self.logger.warning(f"[VORTEX-SDN] No mesh link configured from s{dpid_int} to s{dst_dpid}")
                return

        # Install learned forwarding flow on this switch
        match = parser.OFPMatch(eth_dst=dst)
        actions = [parser.OFPActionOutput(out_port)]
        if self._should_install_flow(dpid_int, dst):
            self.add_flow(datapath, priority=100, match=match, actions=actions, idle_timeout=60)
            self.logger.info(f"[VORTEX-SDN] Learned flow on s{dpid_int}: dst={dst} -> out_port={out_port}")

        # If sender is on access port, also install reverse flow on this switch
        if in_port == ACCESS_PORT:
            match_rev = parser.OFPMatch(eth_dst=src)
            actions_rev = [parser.OFPActionOutput(ACCESS_PORT)]
            if self._should_install_flow(dpid_int, src):
                self.add_flow(datapath, priority=100, match=match_rev, actions=actions_rev, idle_timeout=60)

        # Also proactively install learned forwarding flows on destination switch if different
        if dpid_int != dst_dpid and dst_dpid in self.datapaths:
            target_dp = self.datapaths[dst_dpid]
            # On target switch: flow towards dst goes to its access port
            target_match = target_dp.ofproto_parser.OFPMatch(eth_dst=dst)
            target_actions = [target_dp.ofproto_parser.OFPActionOutput(dst_port)]
            if self._should_install_flow(dst_dpid, dst):
                self.add_flow(target_dp, priority=100, match=target_match, actions=target_actions, idle_timeout=60)

            # On target switch: flow back towards src goes via reverse direct mesh link
            rev_mesh_port = MESH_LINKS.get(dst_dpid, {}).get(dpid_int)
            if rev_mesh_port:
                rev_match = target_dp.ofproto_parser.OFPMatch(eth_dst=src)
                rev_actions = [target_dp.ofproto_parser.OFPActionOutput(rev_mesh_port)]
                if self._should_install_flow(dst_dpid, src):
                    self.add_flow(target_dp, priority=100, match=rev_match, actions=rev_actions, idle_timeout=60)


        # Output current packet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data
        )
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Processes OFPFlowStatsReply."""
        body = ev.msg.body
        dpid = format(ev.msg.datapath.id, "016x")
        flows = []

        for stat in body:
            flows.append({
                "table_id": stat.table_id,
                "priority": stat.priority,
                "duration_sec": stat.duration_sec,
                "idle_timeout": stat.idle_timeout,
                "hard_timeout": stat.hard_timeout,
                "packet_count": stat.packet_count,
                "byte_count": stat.byte_count,
                "match": dict(stat.match.items()) if hasattr(stat.match, 'items') else {}
            })
        self.flow_stats[dpid] = flows

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Processes OFPPortStatsReply."""
        body = ev.msg.body
        dpid = format(ev.msg.datapath.id, "016x")
        ports = []
        for stat in body:
            ports.append({
                "port_no": stat.port_no,
                "rx_packets": stat.rx_packets,
                "tx_packets": stat.tx_packets,
                "rx_bytes": stat.rx_bytes,
                "tx_bytes": stat.tx_bytes,
                "rx_errors": stat.rx_errors,
                "tx_errors": stat.tx_errors
            })
        if dpid in self.switches:
            self.switches[dpid]["ports"] = ports

if __name__ == "__main__":
    print("VORTEX-SDN Ryu OpenFlow 1.3 Controller Application Module")
    print("To run with Ryu: ryu-manager controller/vortex_controller.py --ofp-tcp-listen-port 6653")