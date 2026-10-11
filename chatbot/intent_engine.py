"""
VORTEX-SDN AI Assistant Intent Engine
Parses user queries and extracts intents, entities, device references, and context clues.
"""

import re

class IntentEngine:
    INTENT_PATTERNS = [
        # Predictive Intelligence & Early Warning Intent
        ("PREDICTIVE_INTELLIGENCE", [
            r"predictive (risk|intelligence|warning|forecast|anomal(y|ies))",
            r"what are the current predictive risks",
            r"is traffic (increasing|growing|rising)",
            r"will (bandwidth|traffic|latency) become a problem",
            r"which device has the highest predicted risk",
            r"highest (predicted )?risk device",
            r"are there any early warnings",
            r"early warning",
            r"why is (switch |host )?(s[1-4]|h[1-4]) (high|moderate|elevated) risk",
            r"explain the (traffic |network )?forecast",
            r"what is the confidence of this prediction",
            r"forecast",
            r"trend analysis"
        ]),
        # Digital Twin & What-If Simulation Intent
        ("DIGITAL_TWIN_SIMULATION", [
            r"simulate (failure of |outage of )?(s[1-4]|h[1-4])",
            r"simulate (link failure|switch failure|host failure|congestion|ddos|packet loss|latency)",
            r"what happens if (switch |host )?(s[1-4]|h[1-4]) (fails|goes down|is disabled|dies)",
            r"what happens if (switch |host )?(s[1-4]|h[1-4])",
            r"what happens if (the )?link (between )?(s[1-4]) (and |to )?(s[1-4]) fails",
            r"will the network survive",
            r"which alternate path",
            r"what if packet loss reaches",
            r"which switch is (the )?most critical",
            r"which failure would cause (the )?largest impact",
            r"explain this simulation",
            r"digital twin",
            r"single point of failure",
            r"resilience score",
            r"shutdown (switch |host )?(s[1-4]|h[1-4])",
            r"kill (switch |host )?(s[1-4]|h[1-4])"
        ]),
        # Specific explanation queries (Check before general health/qos)
        ("HEALTH_EXPLANATION", [
            r"why is .*health (low|down|dropping|degraded|decreasing)",
            r"why is .*security (low|down|degraded)",
            r"why is network health",
            r"what is causing.*(latency|packet loss|loss|degradation|jitter|drop)",
            r"why (is|are) .*(latency|loss|jitter|packet loss)",
            r"explain.*(health|score|drop|degradation|security status)",
            r"explain current security status",
            r"what is causing the latency"
        ]),
        ("RECOMMENDATIONS", [
            r"what should i investigate",
            r"what to investigate",
            r"where should i start",
            r"what should i do",
            r"recommendation",
            r"recommend",
            r"how to fix",
            r"mitigate",
            r"action to take"
        ]),
        ("ACTIVE_THREATS", [
            r"active threat",
            r"are there any (active )?threats",
            r"any (active )?threats",
            r"any attacks",
            r"security check",
            r"security status",
            r"malicious flow",
            r"how many malicious",
            r"attackers?",
            r"ddos",
            r"port scan",
            r"brute force",
            r"security alert"
        ]),
        ("INCIDENTS", [
            r"critical incident",
            r"recent incident",
            r"active incident",
            r"open incident",
            r"incident(s)?",
            r"today's incident",
            r"inc[-_][0-9a-zA-Z]+",
            r"what caused",
            r"root cause",
            r"rca",
            r"why was .* incident"
        ]),
        ("RECENT_EVENTS", [
            r"what happened recently",
            r"what happened",
            r"recent event",
            r"event log",
            r"latest event",
            r"recent activities",
            r"audit history"
        ]),
        ("DEVICE_STATUS", [
            r"status of (s[1-4]|h[1-4]|c0|controller|switch [1-4]|host [1-4])",
            r"what happened to (switch )?(s[1-4]|h[1-4])",
            r"(which|any) devices are (currently )?offline",
            r"offline device",
            r"disconnected device",
            r"switch [1-4]",
            r"\bs[1-4]\b",
            r"host [1-4]",
            r"\bh[1-4]\b",
            r"controller status",
            r"controller health"
        ]),
        ("FLOW_INTELLIGENCE", [
            r"top flow",
            r"highest traffic",
            r"highest bandwidth",
            r"consuming the most bandwidth",
            r"top talker",
            r"heavy traffic",
            r"top source",
            r"active flow",
            r"which application is consuming",
            r"show me the highest traffic",
            r"bandwidth hog",
            r"flow table"
        ]),
        ("POLICIES_QOS", [
            r"what qos policies are active",
            r"qos polic(y|ies)",
            r"active polic(y|ies)",
            r"priority polic(y|ies)",
            r"dscp rule"
        ]),
        ("QOS_STATUS", [
            r"qos status",
            r"qos check",
            r"qos health",
            r"what is (the )?qos",
            r"what is packet loss",
            r"packet loss",
            r"latency",
            r"jitter",
            r"voice quality",
            r"video quality"
        ]),
        ("THROUGHPUT_METRICS", [
            r"what is (the )?current throughput",
            r"throughput",
            r"bandwidth utilization",
            r"total bandwidth",
            r"data rate"
        ]),
        ("DEMO_ANALYSIS", [
            r"run a security analysis",
            r"demo security analysis",
            r"simulation analysis",
            r"demo status"
        ]),
        ("NETWORK_HEALTH", [
            r"network health",
            r"how is the network",
            r"what is the current network health",
            r"network status",
            r"overall status",
            r"system health",
            r"\bhealth\b"
        ]),
        ("CONTROLLER_TOPOLOGY", [
            r"topology",
            r"mesh",
            r"links",
            r"openflow switches",
            r"connected hosts",
            r"mininet"
        ]),
        ("HELP_GREETING", [
            r"hello",
            r"hi",
            r"hey",
            r"help",
            r"who are you",
            r"what can you do",
            r"capabilities"
        ])
    ]

    def identify_intent(self, message: str) -> str:
        msg_lower = message.lower().strip()
        for intent, patterns in self.INTENT_PATTERNS:
            for pat in patterns:
                if re.search(pat, msg_lower):
                    return intent
        return "GENERAL_INQUIRY"

    def extract_entities(self, message: str) -> dict:
        """Extracts devices, IP addresses, or metrics targeted in query."""
        msg_lower = message.lower().strip()
        entities = {}

        # Check for switch s1-s4 or switch 1-4
        sw_match = re.search(r"\b(?:switch\s*)?s([1-4])\b|\bswitch\s*([1-4])\b", msg_lower)
        if sw_match:
            num = sw_match.group(1) or sw_match.group(2)
            entities["device_type"] = "switch"
            entities["device_id"] = f"s{num}"

        # Check for host h1-h4 or host 1-4
        host_match = re.search(r"\b(?:host\s*)?h([1-4])\b|\bhost\s*([1-4])\b", msg_lower)
        if host_match:
            num = host_match.group(1) or host_match.group(2)
            entities["device_type"] = "host"
            entities["device_id"] = f"h{num}"

        # Check for controller
        if "controller" in msg_lower or re.search(r"\bc0\b", msg_lower):
            entities["device_type"] = "controller"
            entities["device_id"] = "c0"

        # Check for IP address
        ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", message)
        if ip_match:
            entities["ip_address"] = ip_match.group(0)

        return entities
