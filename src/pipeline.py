"""
End-to-End EAQKD + ML Defense + AES Integrated Pipeline.
Coordinates:
  1. Quantum Channel Configuration
  2. Attack Injection (Threat Simulation)
  3. EAQKD Entanglement Distribution & Sifting
  4. Real-time XGBoost Attack Detection & Diagnostics
  5. Conditional AES-256-GCM Message Encryption & Decryption
"""

from typing import Dict, Any, Optional
from .physics_channel import QuantumChannel
from .attacks import (
    BaseAttack,
    InterceptResendAttack,
    DetectorBlindingAttack,
    JammingAttack,
    PNSAttack
)
from .ml_detector import MLAttackDetector
from .eaqkd_protocol import EAQKDProtocol, EAQKDSessionResult
from .aes_cipher import AESQuantumCipher

class EAQKDSecureSystem:
    """Integrated End-to-End System combining EAQKD, XGBoost Defense, and AES-256."""
    
    def __init__(self, attack_threshold: float = 0.50, max_tolerable_qber: float = 11.0):
        self.attack_threshold = attack_threshold
        self.max_tolerable_qber = max_tolerable_qber
        self.detector = MLAttackDetector()
        
    def _create_attack_instance(self, attack_type: str, intensity: float = 0.85) -> Optional[BaseAttack]:
        attack_type = str(attack_type).strip()
        if attack_type.lower() in ["none", "normal", "clean"]:
            return None
        elif "intercept" in attack_type.lower():
            return InterceptResendAttack(intensity=intensity)
        elif "blind" in attack_type.lower():
            return DetectorBlindingAttack(intensity=intensity)
        elif "jam" in attack_type.lower() or "dos" in attack_type.lower() or "trojan" in attack_type.lower():
            return JammingAttack(intensity=intensity)
        elif "pns" in attack_type.lower() or "photon_number" in attack_type.lower():
            return PNSAttack(intensity=intensity)
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")

    def run_secure_session(
        self,
        message: str,
        distance_km: float = 25.0,
        attack_type: str = "None",
        attack_intensity: float = 0.85,
        n_qubits: int = 2048
    ) -> Dict[str, Any]:
        """
        Executes a complete end-to-end communication workflow:
          1. Simulates EAQKD key exchange.
          2. Runs ML attack evaluation on channel telemetry.
          3. If secure: distills 256-bit key and performs AES-256-GCM encryption & decryption.
          4. If attack detected: aborts transmission, preventing data leak.
        """
        attack_obj = self._create_attack_instance(attack_type, intensity=attack_intensity)
        
        protocol = EAQKDProtocol(
            distance_km=distance_km,
            attack_probability_threshold=self.attack_threshold,
            max_tolerable_qber=self.max_tolerable_qber,
            ml_detector=self.detector
        )
        
        session_result: EAQKDSessionResult = protocol.run_exchange(n_pairs=n_qubits, attack=attack_obj)
        
        response = {
            'distance_km': distance_km,
            'simulated_attack_scenario': attack_type,
            'channel_telemetry': session_result.channel_metrics,
            'ml_attack_probability': session_result.ml_diagnosis['attack_probability'],
            'ml_detected_attack_type': session_result.ml_diagnosis['predicted_attack_type'],
            'ml_threat_level': session_result.ml_diagnosis['threat_level'],
            'ml_security_action': session_result.ml_diagnosis['security_action'],
            'ml_status_message': session_result.ml_diagnosis['status_message'],
            'class_probabilities': session_result.ml_diagnosis['class_probabilities'],
            'feature_contributions': session_result.ml_diagnosis['feature_contributions'],
            'key_distribution_success': session_result.success,
            'abort_reason': session_result.abort_reason
        }
        
        if session_result.success:
            # Distill 256-bit key and encrypt message with AES-256-GCM
            alice_cipher = AESQuantumCipher(session_result.alice_key)
            bob_cipher = AESQuantumCipher(session_result.bob_key)
            
            enc_result = alice_cipher.encrypt(message)
            dec_result = bob_cipher.decrypt(enc_result['ciphertext_hex'], enc_result['nonce_hex'])
            
            response['quantum_key_hex'] = session_result.distilled_key_hex
            response['key_fingerprint'] = session_result.key_fingerprint
            response['aes_encryption'] = {
                'plaintext': message,
                'ciphertext_hex': enc_result['ciphertext_hex'],
                'nonce_hex': enc_result['nonce_hex'],
                'key_fingerprint': enc_result['key_fingerprint'],
                'decrypted_plaintext': dec_result['plaintext'],
                'authentication_verified': dec_result['authenticated']
            }
        else:
            response['quantum_key_hex'] = None
            response['key_fingerprint'] = None
            response['aes_encryption'] = {
                'plaintext': "[WITHHELD: TRANSMISSION ABORTED BY ML SECURITY GUARD]",
                'ciphertext_hex': None,
                'nonce_hex': None,
                'key_fingerprint': None,
                'decrypted_plaintext': None,
                'authentication_verified': False
            }
            
        return response

    def evaluate_custom_telemetry(
        self,
        qber: float,
        photon_loss_db: float,
        noise_level_cps: float,
        distance_km: float,
        key_rate_kbps: float,
        delay_ns: float
    ) -> Dict[str, Any]:
        """
        Direct evaluation of custom or measured channel telemetry using the trained ML model.
        """
        metrics = {
            'qber': qber,
            'photon_loss_db': photon_loss_db,
            'noise_level_cps': noise_level_cps,
            'distance_km': distance_km,
            'key_rate_kbps': key_rate_kbps,
            'delay_ns': delay_ns
        }
        return self.detector.predict(metrics, threshold=self.attack_threshold)
