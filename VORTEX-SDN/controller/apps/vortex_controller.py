from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3


class VortexController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(VortexController, self).__init__(*args, **kwargs)

        self.switches = {}

        self.logger.info("======================================")
        self.logger.info("        VORTEX SDN CONTROLLER")
        self.logger.info("        Controller starting...")
        self.logger.info("        OpenFlow version: 1.3")
        self.logger.info("======================================")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        dpid = datapath.id

        self.switches[dpid] = datapath

        self.logger.info("--------------------------------------")
        self.logger.info("SWITCH CONNECTED")
        self.logger.info("Datapath ID: %s", dpid)
        self.logger.info("OpenFlow version: 1.3")
        self.logger.info("Total switches: %d", len(self.switches))
        self.logger.info("--------------------------------------")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def state_change_handler(self, ev):

        datapath = ev.datapath

        if datapath is None:
            return

        dpid = datapath.id

        self.logger.info(
            "Switch state changed: DPID=%s",
            dpid
        )
        