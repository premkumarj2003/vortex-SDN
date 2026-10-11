"""
VORTEX-SDN QoS Classifier
Evaluates flow characteristics using the QoS ML model and tags flows with traffic categories.
"""

from ai.inference import ai_engine

class QoSClassifier:
    def classify_flow(self, flow: dict) -> dict:
        """
        Classifies flow into VOICE, VIDEO, WEB, FILE_TRANSFER, EMAIL, P2P, BEST_EFFORT, CRITICAL.
        Attaches priority code (EF, AF, BE) and recommended queue.
        """
        prediction = ai_engine.predict_qos(flow)
        flow["traffic_class"] = prediction["traffic_class"]
        flow["qos_confidence"] = prediction["confidence"]
        flow["priority_code"] = prediction["priority_code"]
        flow["recommended_queue"] = prediction["recommended_queue"]
        flow["dscp_mark"] = prediction["dscp_mark"]
        return flow

qos_classifier = QoSClassifier()
