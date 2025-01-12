import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

class ThreatType(Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    DDOS = "ddos"
    INTRUSION = "intrusion"
    RANSOMWARE = "ransomware"

class ThreatSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ThreatIndicator:
    type: ThreatType
    source: str
    timestamp: datetime.datetime
    description: str
    indicators: List[str]  # IPs, URLs, file hashes, etc.
    severity: ThreatSeverity
    confidence: float  # 0.0 to 1.0

class ThreatIntelligence:
    def __init__(self):
        self.threats: List[ThreatIndicator] = []
        self.threat_scores: Dict[str, float] = {}

    def add_threat(self, threat: ThreatIndicator) -> None:
        """Add a new threat indicator to the intelligence database."""
        self.threats.append(threat)
        self._update_threat_scores()

    def _calculate_threat_score(self, threat: ThreatIndicator) -> float:
        """Calculate a threat score based on severity, confidence, and freshness."""
        # Base score from severity
        severity_score = threat.severity.value * 2.5  # Scale to 0-10

        # Confidence factor (0-1)
        confidence_factor = threat.confidence

        # Time decay factor (reduces score of older threats)
        age_hours = (datetime.datetime.now() - threat.timestamp).total_seconds() / 3600
        time_decay = max(0.1, 1 - (age_hours / (24 * 7)))  # Decay over a week

        return severity_score * confidence_factor * time_decay

    def _update_threat_scores(self) -> None:
        """Update threat scores for all indicators."""
        for threat in self.threats:
            for indicator in threat.indicators:
                score = self._calculate_threat_score(threat)
                # Keep the highest score if indicator appears multiple times
                self.threat_scores[indicator] = max(
                    score, self.threat_scores.get(indicator, 0)
                )

    def check_indicator(self, indicator: str) -> Optional[float]:
        """Check if an indicator is known and return its threat score."""
        return self.threat_scores.get(indicator)

    def get_high_priority_threats(self, threshold: float = 7.0) -> List[ThreatIndicator]:
        """Get all threats above a certain score threshold."""
        high_priority = []
        for threat in self.threats:
            if any(self.threat_scores.get(i, 0) >= threshold for i in threat.indicators):
                high_priority.append(threat)
        return high_priority

    def generate_report(self) -> str:
        """Generate a simple threat intelligence report."""
        report = ["Threat Intelligence Report", "=" * 25, ""]
        
        # Group threats by type
        threats_by_type = {}
        for threat in self.threats:
            if threat.type not in threats_by_type:
                threats_by_type[threat.type] = []
            threats_by_type[threat.type].append(threat)

        for threat_type, threats in threats_by_type.items():
            report.append(f"\n{threat_type.value.upper()} Threats:")
            for threat in threats:
                max_score = max(self.threat_scores.get(i, 0) for i in threat.indicators)
                report.append(
                    f"- Severity: {threat.severity.name}, "
                    f"Confidence: {threat.confidence:.2f}, "
                    f"Score: {max_score:.2f}"
                )
                report.append(f"  Description: {threat.description}")

        return "\n".join(report)

# Example usage
def main():
    # Initialize the threat intelligence system
    ti = ThreatIntelligence()

    # Add some sample threats
    sample_threat = ThreatIndicator(
        type=ThreatType.MALWARE,
        source="security_vendor_1",
        timestamp=datetime.datetime.now(),
        description="New ransomware variant detected",
        indicators=["malicious-domain.com", "192.168.1.100"],
        severity=ThreatSeverity.HIGH,
        confidence=0.85
    )

    ti.add_threat(sample_threat)

    # Generate and print a report
    print(ti.generate_report())

    # Check a specific indicator
    indicator = "malicious-domain.com"
    score = ti.check_indicator(indicator)
    if score:
        print(f"\nThreat score for {indicator}: {score:.2f}")

if __name__ == "__main__":
    main()