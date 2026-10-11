"""
VORTEX-SDN Digital Twin Network Graph Engine
Provides pathfinding, Dijkstra shortest path, alternate rerouting,
network partition analysis, critical node evaluation, and single-point-of-failure detection.
"""

import heapq
from collections import deque

def normalize_link_id(src: str, dst: str) -> str:
    """Returns canonical link identifier, e.g. 's1-s2'."""
    s, d = str(src).lower(), str(dst).lower()
    return f"{s}-{d}" if s <= d else f"{d}-{s}"

class NetworkGraph:
    def __init__(self, nodes: list, links: list, excluded_nodes: set = None, excluded_links: set = None):
        self.nodes = {n["id"]: n for n in nodes}
        self.links = links
        self.excluded_nodes = {str(n).lower() for n in (excluded_nodes or set())}
        self.excluded_links = {str(l).lower() for l in (excluded_links or set())}
        self.adj = {}
        self._build_graph()

    def _build_graph(self):
        for node_id in self.nodes:
            if node_id.lower() not in self.excluded_nodes:
                self.adj[node_id] = []

        for link in self.links:
            src = link.get("source")
            dst = link.get("target")
            l_type = link.get("type", "backbone")

            # Exclude control channel links from data-plane packet forwarding calculations
            if l_type == "control":
                continue

            link_id = normalize_link_id(src, dst)
            if src.lower() in self.excluded_nodes or dst.lower() in self.excluded_nodes:
                continue
            if link_id in self.excluded_links:
                continue

            lat = float(link.get("latency_ms", 2.0))
            bw = float(link.get("bandwidth_mbps", 1000.0))

            if src in self.adj:
                self.adj[src].append({"neighbor": dst, "link_id": link_id, "latency": lat, "bandwidth": bw, "type": l_type})
            if dst in self.adj:
                self.adj[dst].append({"neighbor": src, "link_id": link_id, "latency": lat, "bandwidth": bw, "type": l_type})

    def dijkstra_shortest_path(self, src: str, dst: str, weight: str = "latency") -> tuple[list[str], float]:
        """Calculates shortest path using Dijkstra's algorithm. Returns (path, cost)."""
        if src not in self.adj or dst not in self.adj:
            return [], float("inf")
        if src == dst:
            return [src], 0.0

        pq = [(0.0, src, [src])]
        visited = set()

        while pq:
            cost, current, path = heapq.heappop(pq)
            if current in visited:
                continue
            visited.add(current)

            if current == dst:
                return path, cost

            for edge in self.adj.get(current, []):
                neighbor = edge["neighbor"]
                if neighbor not in visited:
                    edge_cost = edge["latency"] if weight == "latency" else 1.0
                    heapq.heappush(pq, (cost + edge_cost, neighbor, path + [neighbor]))

        return [], float("inf")

    def find_all_paths(self, src: str, dst: str, max_depth: int = 5) -> list[list[str]]:
        """Finds all simple paths between src and dst up to max_depth."""
        if src not in self.adj or dst not in self.adj:
            return []

        results = []
        queue = deque([(src, [src])])

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue

            if current == dst:
                results.append(path)
                continue

            for edge in self.adj.get(current, []):
                neighbor = edge["neighbor"]
                if neighbor not in path:
                    queue.append((neighbor, path + [neighbor]))

        return results

    def is_connected(self, node_subset: list = None) -> tuple[bool, list[set]]:
        """Checks if all operational non-controller nodes are in a single connected component."""
        targets = [n for n in (node_subset or self.adj.keys()) if n != "c0"]
        if not targets:
            return True, []

        visited = set()
        components = []

        for node in targets:
            if node not in visited:
                comp = set()
                q = deque([node])
                visited.add(node)
                comp.add(node)

                while q:
                    curr = q.popleft()
                    for edge in self.adj.get(curr, []):
                        nbr = edge["neighbor"]
                        if nbr in targets and nbr not in visited:
                            visited.add(nbr)
                            comp.add(nbr)
                            q.append(nbr)

                components.append(comp)

        is_conn = len(components) <= 1
        return is_conn, components

def analyze_critical_infrastructure(nodes: list, links: list) -> dict:
    """
    Evaluates Critical Node Rankings (S1-S4) and identifies Single Points of Failure (SPOFs).
    """
    base_graph = NetworkGraph(nodes, links)
    switches = [n["id"] for n in nodes if n.get("type") == "switch"]
    hosts = [n["id"] for n in nodes if n.get("type") == "host"]

    criticality_rankings = []
    spofs = []

    for sw in switches:
        # Simulate switch outage
        sim_graph = NetworkGraph(nodes, links, excluded_nodes={sw})
        is_conn, components = sim_graph.is_connected()

        # Check connectivity among all host pairs
        severed_pairs = 0
        total_pairs = 0
        rerouted_pairs = 0

        for i, h1 in enumerate(hosts):
            for h2 in hosts[i+1:]:
                total_pairs += 1
                base_path, _ = base_graph.dijkstra_shortest_path(h1, h2)
                sim_path, _ = sim_graph.dijkstra_shortest_path(h1, h2)

                if not sim_path:
                    severed_pairs += 1
                elif sim_path != base_path:
                    rerouted_pairs += 1

        # Determine node criticality score
        if severed_pairs > 0:
            crit_level = "HIGH"
            reason = f"Outage partitions {severed_pairs} host pair(s) and isolates attached end-systems."
            spofs.append({
                "component": sw.upper(),
                "type": "SWITCH",
                "impact": f"Isolates attached host and disconnects {severed_pairs}/{total_pairs} host paths",
                "severity": "HIGH"
            })
        elif rerouted_pairs > 0:
            crit_level = "MEDIUM"
            reason = f"Full mesh survives with traffic rerouting across {rerouted_pairs} active path(s)."
        else:
            crit_level = "LOW"
            reason = "Redundant mesh topology absorbs failure with zero disruption."

        criticality_rankings.append({
            "device": sw.upper(),
            "role": base_graph.nodes.get(sw, {}).get("role", "CORE_SWITCH"),
            "criticality": crit_level,
            "severed_paths": severed_pairs,
            "rerouted_paths": rerouted_pairs,
            "resilience": "FAILOVER_AVAILABLE" if severed_pairs == 0 else "PARTITION_DETECTED",
            "reason": reason
        })

    # Link Criticality Check
    for link in links:
        if link.get("type") == "backbone":
            l_id = normalize_link_id(link["source"], link["target"])
            sim_graph = NetworkGraph(nodes, links, excluded_links={l_id})
            is_conn, _ = sim_graph.is_connected()
            if not is_conn:
                spofs.append({
                    "component": f"{link['source'].upper()} - {link['target'].upper()}",
                    "type": "LINK",
                    "impact": "Core network partition detected upon link failure",
                    "severity": "HIGH"
                })

    return {
        "critical_nodes": criticality_rankings,
        "single_points_of_failure": spofs,
        "has_spof": len(spofs) > 0,
        "mesh_redundancy_level": "N+1 FULL MESH" if len(spofs) <= 4 else "PARTIAL MESH"
    }
