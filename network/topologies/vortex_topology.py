r"""
VORTEX-SDN Mininet Topology Definition
Creates an enterprise 4-switch mesh topology with 4 hosts connected to Ryu RemoteController:

    h1 (10.0.0.1) --- [s1] ====== [s2] --- h3 (10.0.0.3)
                        |    \  /   |
                        |     \/    |
                        |    /  \   |
    h2 (10.0.0.2) --- [s3] ====== [s4] --- h4 (10.0.0.4)
"""

import importlib

try:
    _topo_mod = importlib.import_module("mininet.topo")
    _net_mod = importlib.import_module("mininet.net")
    _node_mod = importlib.import_module("mininet.node")
    _cli_mod = importlib.import_module("mininet.cli")
    _log_mod = importlib.import_module("mininet.log")
    _link_mod = importlib.import_module("mininet.link")

    Topo = _topo_mod.Topo
    Mininet = _net_mod.Mininet
    RemoteController = _node_mod.RemoteController
    OVSSwitch = _node_mod.OVSSwitch
    CLI = _cli_mod.CLI
    setLogLevel = _log_mod.setLogLevel
    info = _log_mod.info
    TCLink = _link_mod.TCLink
    MININET_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    MININET_AVAILABLE = False

    class Topo:  # type: ignore
        """Fallback mock Topo class for environments without Mininet (e.g. Windows)."""
        def __init__(self, *args, **kwargs): pass
        def addSwitch(self, name, **opts): return name
        def addHost(self, name, **opts): return name
        def addLink(self, node1, node2, **opts): return (node1, node2)

    def setLogLevel(*args, **kwargs): pass
    def info(*args, **kwargs): pass

    class Mininet:  # type: ignore
        def __init__(self, *args, **kwargs): pass
        def start(self): pass
        def pingAll(self): pass
        def stop(self): pass
        def addController(self, *args, **kwargs): return None
        def addSwitch(self, *args, **kwargs): return None

    class RemoteController:  # type: ignore
        def __init__(self, *args, **kwargs): pass

    class OVSSwitch:  # type: ignore
        def __init__(self, *args, **kwargs): pass

    class CLI:  # type: ignore
        def __init__(self, *args, **kwargs): pass

    class TCLink:  # type: ignore
        def __init__(self, *args, **kwargs): pass

class VortexSDNTopology(Topo):
    def build(self):
        # 1. Add 4 OpenFlow Switches (OVS)
        s1 = self.addSwitch("s1", dpid="0000000000000001", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", dpid="0000000000000002", protocols="OpenFlow13")
        s3 = self.addSwitch("s3", dpid="0000000000000003", protocols="OpenFlow13")
        s4 = self.addSwitch("s4", dpid="0000000000000004", protocols="OpenFlow13")

        # 2. Add 4 End Hosts with IP & MAC addresses
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01") # Web/App Server
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02") # VoIP/DB Client
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03") # Video Client
        h4 = self.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04") # External/Attacker Node

        # 3. Connect Hosts to Switches (100 Mbps links, 2ms delay)
        self.addLink(h1, s1, bw=100, delay="2ms", loss=0, max_queue_size=1000)
        self.addLink(h2, s3, bw=100, delay="2ms", loss=0, max_queue_size=1000)
        self.addLink(h3, s2, bw=100, delay="2ms", loss=0, max_queue_size=1000)
        self.addLink(h4, s4, bw=100, delay="2ms", loss=0, max_queue_size=1000)

        # 4. Inter-Switch Backbone Links (1 Gbps links, 5ms delay)
        self.addLink(s1, s2, bw=1000, delay="5ms")
        self.addLink(s1, s3, bw=1000, delay="5ms")
        self.addLink(s2, s4, bw=1000, delay="5ms")
        self.addLink(s3, s4, bw=1000, delay="5ms")
        self.addLink(s1, s4, bw=1000, delay="5ms")
        self.addLink(s2, s3, bw=1000, delay="5ms")

def run_network():
    if not MININET_AVAILABLE:
        print("[VORTEX-SDN] Mininet is not natively available in this environment.")
        print("Please run on a Linux / WSL / Ubuntu environment with Mininet and OVS installed.")
        return

    setLogLevel("info")
    info("*** Creating VORTEX-SDN Topology ***\n")
    topo = VortexSDNTopology()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        link=TCLink,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
        autoSetMacs=True,
        autoStaticArp=True
    )

    info("*** Starting Network ***\n")
    net.start()
    info("*** Testing Network Connectivity ***\n")
    net.pingAll()
    info("*** Running Mininet CLI ***\n")
    CLI(net)
    info("*** Stopping Network ***\n")
    net.stop()

if __name__ == "__main__":
    run_network()
