"""
VORTEX-SDN Enterprise Ryu OpenFlow 1.3 Controller Application
Manages datapath discovery, port statistics, flow rule installations,
real-time OpenFlow telemetry collection, security mitigation drops, and QoS queue assignments.
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
    from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp  # type: ignore
    # pyrefly: ignore [missing-import]
    from ryu.lib import hub  # type: ignore
    # pyrefly: ignore [missing-import]
    from ryu.app.wsgi import ControllerBase, WSGIApplication, route  # type: ignore
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False
    app_manager = type('obj', (object,), {'RyuApp': object})

class VortexRyuController(app_manager.RyuApp):
    OFP_VERSIONS = [1.3] if not RYU_AVAILABLE else [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        if RYU_AVAILABLE:
            super(VortexRyuController, self).__init__(*args, **kwargs)
        self.datapaths = {} # dpid -> datapath
        self.switches = {} # dpid -> {ports, name, status, last_seen}
        self.hosts = {} # mac/ip -> host_info
        self.links = [] # [(src_dpid, src_port, dst_dpid, dst_port)]
        self.flow_stats = {} # dpid -> list of flows
        self.port_stats = {} # (dpid, port) -> stats
        self.mac_to_port = {} # dpid -> {mac -> port}
        self.is_running = True
        
        # Start background polling thread if Ryu is active
        if RYU_AVAILABLE:
            self.monitor_thread = hub.spawn(self._stats_monitor_loop)

    def _stats_monitor_loop(self):
        """Periodically requests flow and port stats from all connected switches."""
        while self.is_running:
            for dp in self.datapaths.values():
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

    def switch_features_handler(self, ev):
        """Handles switch feature reply, installs table-miss flow entry (send to controller)."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = format(datapath.id, "016x")
        self.datapaths[dpid] = datapath
        self.switches[dpid] = {
            "dpid": dpid,
            "name": f"s{datapath.id}",
            "status": "ONLINE",
            "connected_at": datetime.now(timezone.utc).isoformat(),
            "ports": []
        }

        # Install table-miss flow entry: Priority 0 -> Send to Controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"[VORTEX-SDN] Switch connected: DPID={dpid} (s{datapath.id})")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Installs OpenFlow 1.3 flow rule."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id, priority=priority,
                match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match,
                instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout
            )
        datapath.send_msg(mod)

    def packet_in_handler(self, ev):
        """Handles incoming packet-in messages from OpenFlow switches."""
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
        dpid = format(datapath.id, "016x")

        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC address
        self.mac_to_port[dpid][src] = in_port

        # Discover host
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.hosts[src] = {
                "mac": src,
                "ip": ip_pkt.src,
                "switch_dpid": dpid,
                "switch_port": in_port,
                "last_seen": datetime.now(timezone.utc).isoformat()
            }

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Install flow rule if destination port is known
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id, idle_timeout=30)
                return
            else:
                self.add_flow(datapath, 10, match, actions, idle_timeout=30)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data
        )
        datapath.send_msg(out)

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
