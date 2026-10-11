import importlib

try:
    _net_mod = importlib.import_module("mininet.net")
    _node_mod = importlib.import_module("mininet.node")
    _cli_mod = importlib.import_module("mininet.cli")
    _log_mod = importlib.import_module("mininet.log")
    _link_mod = importlib.import_module("mininet.link")

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


def create_vortex_network():

    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    info("*** Adding VORTEX controller\n")

    controller = net.addController(
        "vortex",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633
    )

    info("*** Adding switch\n")

    s1 = net.addSwitch(
        "s1",
        protocols="OpenFlow13"
    )

    info("*** Adding hosts\n")

    h1 = net.addHost(
        "h1",
        ip="10.0.0.1/24"
    )

    h2 = net.addHost(
        "h2",
        ip="10.0.0.2/24"
    )

    info("*** Creating links\n")

    net.addLink(h1, s1)
    net.addLink(h2, s1)

    info("*** Starting network\n")

    net.start()

    info("*** VORTEX network started\n")
    info("*** Controller: 127.0.0.1:6633\n")
    info("*** OpenFlow: 1.3\n")

    CLI(net)

    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    create_vortex_network()

