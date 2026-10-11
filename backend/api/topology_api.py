"""
VORTEX-SDN Topology & Devices REST API
"""

from flask import Blueprint, jsonify
from backend.services.topology_service import get_network_topology

topology_bp = Blueprint("topology", __name__)

@topology_bp.route("/api/topology", methods=["GET"])
def get_topology():
    data = get_network_topology()
    return jsonify(data), 200

@topology_bp.route("/api/devices", methods=["GET"])
def get_devices():
    data = get_network_topology()
    switches = [n for n in data["nodes"] if n["type"] == "switch"]
    hosts = [n for n in data["nodes"] if n["type"] == "host"]
    controllers = [n for n in data["nodes"] if n["type"] == "controller"]
    return jsonify({
        "switches": switches,
        "hosts": hosts,
        "controllers": controllers,
        "total_devices": len(data["nodes"])
    }), 200

@topology_bp.route("/api/ports", methods=["GET"])
def get_ports():
    data = get_network_topology()
    return jsonify({"links": data["links"]}), 200
