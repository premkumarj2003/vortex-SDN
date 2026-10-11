from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from telemetry.flow_monitor import FlowMonitor
from telemetry.telemetry_store import TelemetryStore

from security.detection_pipeline import DetectionPipeline
from security.security_event_store import SecurityEventStore

from response.response_engine import ResponseEngine
from response.mitigation_engine import MitigationEngine


class VortexController(app_manager.RyuApp):

    OFP_VERSIONS = [
        ofproto_v1_3.OFP_VERSION
    ]

    def __init__(self, *args, **kwargs):

        super(
            VortexController,
            self
        ).__init__(
            *args,
            **kwargs
        )

        # ==================================================
        # SWITCH MANAGEMENT
        # ==================================================

        self.switches = {}

        self.mac_to_port = {}

        self.flow_monitors = {}

        # ==================================================
        # TELEMETRY
        # ==================================================

        self.telemetry_store = TelemetryStore()

        # ==================================================
        # SECURITY DETECTION
        # ==================================================

        self.detection_pipeline = DetectionPipeline(
            anomaly_window=50,
            anomaly_sensitivity=3.0
        )

        # ==================================================
        # SECURITY EVENT STORAGE
        # ==================================================

        self.security_event_store = (
            SecurityEventStore()
        )

        # ==================================================
        # MITIGATION ENGINE
        #
        # Active so HIGH / CRITICAL events can
        # install OpenFlow DROP rules.
        # ==================================================

        self.mitigation_engine = MitigationEngine(
            enabled=True
        )

        # ==================================================
        # RESPONSE ENGINE
        #
        # SAFE MODE remains enabled for normal operation.
        # Automatic mitigation is therefore not triggered
        # until explicitly switched to active mode.
        # ==================================================

        self.response_engine = ResponseEngine(
            safe_mode=True,
            mitigation_engine=self.mitigation_engine
        )

        # ==================================================
        # MONITOR THREAD
        # ==================================================

        self.monitor_thread = hub.spawn(
            self._monitor
        )

        # ==================================================
        # STARTUP LOG
        # ==================================================

        self.logger.info(
            "======================================"
        )

        self.logger.info(
            "       VORTEX SDN CONTROLLER"
        )

        self.logger.info(
            "       Controller starting..."
        )

        self.logger.info(
            "       OpenFlow version: 1.3"
        )

        self.logger.info(
            "       Flow Management: ENABLED"
        )

        self.logger.info(
            "       Telemetry Engine: ENABLED"
        )

        self.logger.info(
            "       Telemetry Storage: ENABLED"
        )

        self.logger.info(
            "       Security Engine: ENABLED"
        )

        self.logger.info(
            "       Threat Scoring: ENABLED"
        )

        self.logger.info(
            "       Response Engine: SAFE MODE"
        )

        self.logger.info(
            "       Mitigation Engine: READY"
        )

        self.logger.info(
            "======================================"
        )

    # ======================================================
    # SWITCH CONNECTION
    # ======================================================

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath

        dpid = datapath.id

        self.switches[dpid] = datapath

        self.mac_to_port.setdefault(
            dpid,
            {}
        )

        self.flow_monitors[dpid] = FlowMonitor(
            datapath
        )

        self.logger.info(
            "--------------------------------------"
        )

        self.logger.info(
            "SWITCH CONNECTED"
        )

        self.logger.info(
            "Datapath ID: %s",
            dpid
        )

        self.logger.info(
            "OpenFlow version: 1.3"
        )

        self.logger.info(
            "Total switches: %d",
            len(self.switches)
        )

        self.logger.info(
            "--------------------------------------"
        )

        # ==================================================
        # TABLE-MISS RULE
        # ==================================================

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath,
            priority=0,
            match=match,
            actions=actions,
            idle_timeout=0,
            hard_timeout=0
        )

        self.logger.info(
            "TABLE-MISS RULE INSTALLED | DPID=%s",
            dpid
        )

    # ======================================================
    # FLOW INSTALLATION
    # ======================================================

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        idle_timeout=0,
        hard_timeout=0
    ):

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )

        datapath.send_msg(mod)

    # ======================================================
    # PACKET-IN HANDLER
    # ======================================================

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        msg = ev.msg

        datapath = msg.datapath

        dpid = datapath.id

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        in_port = msg.match[
            "in_port"
        ]

        pkt = packet.Packet(
            msg.data
        )

        eth = pkt.get_protocol(
            ethernet.ethernet
        )

        if eth is None:
            return

        # Ignore LLDP.

        if eth.ethertype == (
            ether_types.ETH_TYPE_LLDP
        ):
            return

        src = eth.src

        dst = eth.dst

        # ==================================================
        # MAC LEARNING
        # ==================================================

        self.mac_to_port.setdefault(
            dpid,
            {}
        )

        self.mac_to_port[dpid][src] = (
            in_port
        )

        self.logger.info(
            "TRAFFIC | "
            "DPID=%s | "
            "SRC=%s | "
            "DST=%s | "
            "IN_PORT=%s",
            dpid,
            src,
            dst,
            in_port
        )

        # ==================================================
        # FORWARDING
        # ==================================================

        if dst in self.mac_to_port[dpid]:

            out_port = (
                self.mac_to_port[dpid][dst]
            )

        else:

            out_port = (
                ofproto.OFPP_FLOOD
            )

        actions = [
            parser.OFPActionOutput(
                out_port
            )
        ]

        # ==================================================
        # INSTALL LEARNED FLOW
        #
        # Persistent flow:
        # idle_timeout=0
        # ==================================================

        if out_port != (
            ofproto.OFPP_FLOOD
        ):

            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst
            )

            self.add_flow(
                datapath,
                priority=10,
                match=match,
                actions=actions,
                idle_timeout=0,
                hard_timeout=0
            )

            self.logger.info(
                "FLOW INSTALLED | "
                "%s -> %s | "
                "PORT %s -> %s",
                src,
                dst,
                in_port,
                out_port
            )

        # ==================================================
        # FORWARD CURRENT PACKET
        # ==================================================

        data = None

        if msg.buffer_id == (
            ofproto.OFP_NO_BUFFER
        ):

            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

    # ======================================================
    # TELEMETRY MONITOR
    # ======================================================

    def _monitor(self):

        while True:

            for dpid, datapath in list(
                self.switches.items()
            ):

                monitor = (
                    self.flow_monitors.get(
                        dpid
                    )
                )

                if monitor is None:

                    monitor = FlowMonitor(
                        datapath
                    )

                    self.flow_monitors[
                        dpid
                    ] = monitor

                request = (
                    monitor
                    .get_flow_stats_request()
                )

                datapath.send_msg(
                    request
                )

            hub.sleep(5)

    # ======================================================
    # FLOW STATISTICS REPLY
    # ======================================================

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER
    )
    def flow_stats_reply_handler(self, ev):

        datapath = ev.msg.datapath

        dpid = datapath.id

        monitor = (
            self.flow_monitors.get(
                dpid
            )
        )

        if monitor is None:
            return

        records = (
            monitor.process_flow_stats(
                ev.msg.body
            )
        )

        for record in records:

            # ==============================================
            # SAVE TELEMETRY
            # ==============================================

            self.telemetry_store.save(
                record
            )

            # ==============================================
            # DETECTION
            # ==============================================

            security_event = (
                self.detection_pipeline.process(
                    record
                )
            )

            anomaly = (
                security_event["anomaly"]
            )

            threat = (
                security_event["threat"]
            )

            # ==============================================
            # SAVE SECURITY EVENT
            # ==============================================

            self.security_event_store.save(
                security_event
            )

            # ==============================================
            # RESPONSE
            #
            # SAFE MODE currently prevents automatic
            # OpenFlow blocking.
            # ==============================================

            response = (
                self.response_engine.respond(
                    security_event=security_event,
                    datapath=datapath,
                    source_mac=record.get(
                        "source_mac"
                    ),
                    destination_mac=record.get(
                        "destination_mac"
                    ),
                    in_port=record.get(
                        "in_port"
                    )
                )
            )

            # ==============================================
            # TELEMETRY LOG
            # ==============================================

            self.logger.info(
                "TELEMETRY | "
                "DPID=%s | "
                "PORT=%s | "
                "SRC=%s | "
                "DST=%s | "
                "PACKETS=%s | "
                "BYTES=%s | "
                "PACKET_RATE=%.2f/s | "
                "BYTE_RATE=%.2f B/s",
                dpid,
                record.get(
                    "in_port"
                ),
                record.get(
                    "source_mac"
                ),
                record.get(
                    "destination_mac"
                ),
                record.get(
                    "packets"
                ),
                record.get(
                    "bytes"
                ),
                record.get(
                    "packet_rate"
                ),
                record.get(
                    "byte_rate"
                )
            )

            # ==============================================
            # SECURITY LOG
            # ==============================================

            self.logger.info(
                "SECURITY | "
                "DPID=%s | "
                "ANOMALY_SCORE=%s | "
                "THREAT_SCORE=%s | "
                "SEVERITY=%s | "
                "ACTION=%s",
                dpid,
                anomaly.get(
                    "anomaly_score"
                ),
                threat.get(
                    "threat_score"
                ),
                threat.get(
                    "severity"
                ),
                threat.get(
                    "recommended_action"
                )
            )

            # ==============================================
            # RESPONSE LOG
            # ==============================================

            self.logger.info(
                "RESPONSE | "
                "DPID=%s | "
                "THREAT_SCORE=%s | "
                "SEVERITY=%s | "
                "ACTION=%s | "
                "EXECUTED=%s | "
                "SAFE_MODE=%s",
                dpid,
                response.get(
                    "threat_score"
                ),
                response.get(
                    "severity"
                ),
                response.get(
                    "action"
                ),
                response.get(
                    "executed"
                ),
                response.get(
                    "safe_mode"
                )
            )

            # ==============================================
            # MITIGATION LOG
            # ==============================================

            mitigation = (
                response.get(
                    "mitigation"
                )
            )

            if mitigation:

                self.logger.info(
                    "MITIGATION | "
                    "DPID=%s | "
                    "SUCCESS=%s | "
                    "ACTION=%s | "
                    "MESSAGE=%s",
                    dpid,
                    mitigation.get(
                        "success"
                    ),
                    mitigation.get(
                        "action"
                    ),
                    mitigation.get(
                        "message"
                    )
                )

            # ==============================================
            # MITIGATION STATUS
            # ==============================================

            mitigation_status = (
                self.mitigation_engine.get_status()
            )

            self.logger.info(
                "MITIGATION STATUS | "
                "DPID=%s | "
                "ENABLED=%s | "
                "BLOCKED_FLOWS=%s",
                dpid,
                mitigation_status.get(
                    "enabled"
                ),
                mitigation_status.get(
                    "blocked_flows"
                )
            )

            # ==============================================
            # ALERT
            # ==============================================

            if anomaly.get(
                "is_anomaly"
            ):

                self.logger.warning(
                    "VORTEX ALERT | "
                    "DPID=%s | "
                    "THREAT=%s | "
                    "SEVERITY=%s | "
                    "REASON=%s",
                    dpid,
                    threat.get(
                        "threat_score"
                    ),
                    threat.get(
                        "severity"
                    ),
                    anomaly.get(
                        "reason"
                    )
                )

    # ======================================================
    # SWITCH STATE CHANGE
    # ======================================================

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER]
    )
    def state_change_handler(self, ev):

        datapath = ev.datapath

        if datapath is None:
            return

        dpid = datapath.id

        self.logger.info(
            "Switch state changed: DPID=%s",
            dpid
        )

        