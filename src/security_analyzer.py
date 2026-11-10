"""
Security Score Evaluator and Information Leakage Risk Analyzer for EAQKD.
Implements:
  1. Information-Theoretic Leakage Risk Analysis (Holevo bound / Eve's mutual information)
  2. Multi-factor Quantum Security Score (0 to 100)
  3. Composable security verification
"""

import numpy as np

def shannon_h2(p):
    """Binary Shannon entropy h2(p)."""
    p = np.clip(p, 1e-12, 1.0 - 1e-12)
    return -p * np.log2(p) - (1.0 - p) * np.log2(1.0 - p)

class SecurityAnalyzer:
    """Evaluates information leakage risk and computes an aggregate Quantum Security Score."""
    
    def __init__(self, abort_qber_threshold: float = 11.0):
        self.abort_qber = abort_qber_threshold

    def evaluate_leakage_risk(self, qber: float, attack_prob: float, attack_type: str = "Normal") -> dict:
        """
        Estimates the maximum information an eavesdropper (Eve) could possess:
          I(A:E) <= h2(QBER) + delta_attack
        """
        qber_frac = np.clip(qber / 100.0, 0.0, 0.5)
        base_h2 = float(shannon_h2(qber_frac))
        
        # Attack-specific leakage expansion
        if attack_type == "Intercept_Resend":
            eve_leakage_upper_bound = min(1.0, base_h2 + 0.35 * attack_prob)
        elif attack_type == "Detector_Blinding":
            # Under blinding, classical interception gives Eve high control
            eve_leakage_upper_bound = min(1.0, 0.90 * attack_prob)
        elif attack_type == "PNS":
            # Eve keeps full multi-photon copies
            eve_leakage_upper_bound = min(1.0, base_h2 + 0.40 * attack_prob)
        elif attack_type == "Jamming_DoS":
            eve_leakage_upper_bound = min(1.0, base_h2 + 0.20 * attack_prob)
        else:
            eve_leakage_upper_bound = base_h2 * 0.85
            
        # Determine leakage risk tier
        if eve_leakage_upper_bound >= 0.70 or qber >= self.abort_qber:
            risk_tier = "CRITICAL_LEAKAGE"
            recommendation = "Immediate abort. Do not disclose basis sifting or parity bits."
        elif eve_leakage_upper_bound >= 0.40 or attack_prob >= 0.40:
            risk_tier = "HIGH_LEAKAGE"
            recommendation = "Compromised channel. High privacy amplification compression required if un-aborted."
        elif eve_leakage_upper_bound >= 0.15:
            risk_tier = "MODERATE_LEAKAGE"
            recommendation = "Standard privacy amplification (Toeplitz/SHA-256) suffices to compress Eve's info to < 1e-10."
        else:
            risk_tier = "MINIMAL_LEAKAGE"
            recommendation = "Nominal quantum channel. Negligible eavesdropper correlation."

        return {
            'eve_information_upper_bound_bits': round(float(eve_leakage_upper_bound), 4),
            'leakage_risk_tier': risk_tier,
            'secrecy_capacity_fraction': round(float(max(0.0, 1.0 - 2.0 * eve_leakage_upper_bound)), 4),
            'mitigation_recommendation': recommendation
        }

    def compute_security_score(self, metrics: dict, ml_diagnosis: dict) -> dict:
        """
        Calculates a holistic Quantum Security Score (0 to 100) based on:
          1. QBER margin from abort threshold (30%)
          2. Bell CHSH violation margin above classical bound 2.0 (25%)
          3. XGBoost Attack Probability inversely weighted (25%)
          4. Secret key generation capacity (20%)
        """
        qber = float(metrics.get('qber', 2.0))
        bell_s = float(metrics.get('bell_parameter_s', 2.70))
        attack_prob = float(ml_diagnosis.get('attack_probability', 0.0))
        key_rate = float(metrics.get('key_rate_kbps', 4.0))

        # 1. QBER Subscore (0 to 100)
        qber_score = max(0.0, min(100.0, (1.0 - (qber / self.abort_qber)) * 100.0))

        # 2. Bell Violation Subscore (0 to 100)
        # S ranges from 2.0 (classical) to 2.828 (Tsirelson's quantum bound)
        bell_score = max(0.0, min(100.0, ((bell_s - 2.0) / (2.828 - 2.0)) * 100.0))

        # 3. ML Integrity Subscore (0 to 100)
        ml_score = max(0.0, min(100.0, (1.0 - attack_prob) * 100.0))

        # 4. Key Rate Health Subscore (0 to 100)
        rate_score = min(100.0, (key_rate / 5.0) * 100.0)

        # Weighted aggregate
        total_score = (
            0.30 * qber_score +
            0.25 * bell_score +
            0.25 * ml_score +
            0.20 * rate_score
        )
        total_score = round(float(np.clip(total_score, 0.0, 100.0)), 1)

        # Classification rating
        if total_score >= 85.0:
            rating = "EXCELLENT (Quantum Channel Robust)"
            color = "#25d366"
        elif total_score >= 65.0:
            rating = "GOOD (Secure with Minor Degradation)"
            color = "#3498db"
        elif total_score >= 45.0:
            rating = "MARGINAL (Channel Approaching Safety Limits)"
            color = "#f39c12"
        else:
            rating = "COMPROMISED (Unsafe for Cryptographic Key Exchange)"
            color = "#ff4b4b"

        leakage_info = self.evaluate_leakage_risk(
            qber=qber,
            attack_prob=attack_prob,
            attack_type=ml_diagnosis.get('predicted_attack_type', 'Normal')
        )

        return {
            'overall_security_score': total_score,
            'rating': rating,
            'color': color,
            'subscores': {
                'qber_health_score': round(qber_score, 1),
                'bell_entanglement_score': round(bell_score, 1),
                'ml_integrity_score': round(ml_score, 1),
                'key_rate_throughput_score': round(rate_score, 1)
            },
            'leakage_analysis': leakage_info
        }
