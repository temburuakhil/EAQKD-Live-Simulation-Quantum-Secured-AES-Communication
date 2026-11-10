"""
Comprehensive Test Suite for EAQKD + ML + AES System.
Tests:
  - Quantum Channel & Bell state physics
  - All four quantum attack models
  - XGBoost ML Detector inference
  - AES-256-GCM cipher encryption, decryption, and tamper detection
  - End-to-end EAQKD protocol under clean and compromised scenarios
"""

import pytest
import numpy as np
from src.physics_channel import QuantumChannel, BellStateSource
from src.attacks import InterceptResendAttack, DetectorBlindingAttack, JammingAttack, PNSAttack
from src.ml_detector import MLAttackDetector
from src.aes_cipher import AESQuantumCipher
from src.eaqkd_protocol import EAQKDProtocol
from src.pipeline import EAQKDSecureSystem

def test_bell_state_source():
    source = BellStateSource(rate_hz=1e6, fidelity=1.0, random_state=42)
    alice, bob = source.generate_pairs(n_pairs=1000)
    assert len(alice) == 1000
    assert len(bob) == 1000
    # In pure |Phi+> state, outcomes match 100%
    assert np.array_equal(alice, bob)

def test_quantum_channel_physics():
    ch = QuantumChannel(distance_km=50.0, fiber_loss_db_per_km=0.20, coupling_loss_db=1.5, random_state=42)
    m = ch.calculate_metrics()
    assert m['distance_km'] == 50.0
    # Expected photon loss ~ 0.2*50 + 1.5 = 11.5 dB
    assert 11.0 <= m['photon_loss_db'] <= 12.0
    assert 0.5 <= m['qber'] <= 10.0
    assert m['bell_parameter_s'] > 2.0  # Must violate Bell inequality

def test_intercept_resend_attack():
    ch = QuantumChannel(distance_km=30.0, random_state=42)
    base_m = ch.calculate_metrics()
    attack = InterceptResendAttack(intensity=0.9)
    attacked_m = attack.perturb_channel(base_m)
    # QBER should spike > 15%
    assert attacked_m['qber'] >= 15.0
    # Bell S should drop <= 2.0 (classical bound)
    assert attacked_m['bell_parameter_s'] <= 2.0
    assert attacked_m['key_rate_kbps'] == 0.0

def test_detector_blinding_attack():
    ch = QuantumChannel(distance_km=20.0, random_state=42)
    base_m = ch.calculate_metrics()
    attack = DetectorBlindingAttack(intensity=0.95)
    attacked_m = attack.perturb_channel(base_m)
    assert attacked_m['noise_level_cps'] < 100.0
    assert attacked_m['qber'] < 1.0
    assert attacked_m['delay_ns'] < 1.5

def test_jamming_attack():
    ch = QuantumChannel(distance_km=25.0, random_state=42)
    base_m = ch.calculate_metrics()
    attack = JammingAttack(intensity=0.85)
    attacked_m = attack.perturb_channel(base_m)
    assert attacked_m['noise_level_cps'] > 10000.0
    assert attacked_m['qber'] > 12.0

def test_pns_attack():
    ch = QuantumChannel(distance_km=80.0, random_state=42)
    base_m = ch.calculate_metrics()
    attack = PNSAttack(intensity=0.85)
    attacked_m = attack.perturb_channel(base_m)
    # Loss should be significantly lower than baseline (17.8 dB)
    assert attacked_m['photon_loss_db'] < 15.0

def test_ml_detector_inference():
    detector = MLAttackDetector()
    
    # Test Normal input
    normal_metrics = {
        'distance_km': 25.0,
        'photon_loss_db': 6.8,
        'noise_level_cps': 850.0,
        'qber': 2.1,
        'key_rate_kbps': 4.5,
        'delay_ns': 2.5
    }
    diag_normal = detector.predict(normal_metrics)
    assert diag_normal['attack_probability'] < 0.20
    assert diag_normal['is_attack'] is False
    assert diag_normal['security_action'] == "PROCEED_WITH_KEY_DISTILLATION"

    # Test Intercept-Resend input
    ir_metrics = {
        'distance_km': 25.0,
        'photon_loss_db': 6.8,
        'noise_level_cps': 850.0,
        'qber': 26.5,
        'key_rate_kbps': 0.0,
        'delay_ns': 4.9
    }
    diag_ir = detector.predict(ir_metrics)
    assert diag_ir['attack_probability'] > 0.80
    assert diag_ir['is_attack'] is True
    assert diag_ir['predicted_attack_type'] == "Intercept_Resend"
    assert diag_ir['security_action'] == "ABORT_KEY_EXCHANGE"

def test_aes_cipher_encryption_and_tampering():
    key = b"01234567890123456789012345678901"  # 32 bytes = 256 bits
    cipher = AESQuantumCipher(key)
    message = "Secret quantum communication payload"
    
    enc = cipher.encrypt(message)
    assert 'ciphertext_hex' in enc
    assert 'nonce_hex' in enc
    
    # Successful decryption
    dec = cipher.decrypt(enc['ciphertext_hex'], enc['nonce_hex'])
    assert dec['authenticated'] is True
    assert dec['plaintext'] == message
    
    # Tamper test: flip a byte in ciphertext
    ct_bytes = bytearray.fromhex(enc['ciphertext_hex'])
    ct_bytes[0] ^= 0xFF  # alter first byte
    tampered_hex = ct_bytes.hex()
    
    tampered_dec = cipher.decrypt(tampered_hex, enc['nonce_hex'])
    assert tampered_dec['authenticated'] is False
    assert tampered_dec['plaintext'] is None
    assert "INTEGRITY FAILURE" in tampered_dec['error']

def test_end_to_end_pipeline():
    system = EAQKDSecureSystem(attack_threshold=0.50)
    
    # Normal channel should succeed
    res_normal = system.run_secure_session("Hello Quantum World", distance_km=20.0, attack_type="None")
    assert res_normal['key_distribution_success'] is True
    assert res_normal['quantum_key_hex'] is not None
    assert res_normal['aes_encryption']['decrypted_plaintext'] == "Hello Quantum World"
    assert res_normal['aes_encryption']['authentication_verified'] is True
    
    # Intercept-Resend should be blocked
    res_attack = system.run_secure_session("Secret Message", distance_km=20.0, attack_type="Intercept_Resend")
    assert res_attack['key_distribution_success'] is False
    assert res_attack['quantum_key_hex'] is None
    assert "WITHHELD" in res_attack['aes_encryption']['plaintext']

def test_security_analyzer():
    from src.security_analyzer import SecurityAnalyzer
    analyzer = SecurityAnalyzer()
    
    score_normal = analyzer.compute_security_score(
        metrics={'qber': 1.8, 'bell_parameter_s': 2.75, 'key_rate_kbps': 4.5},
        ml_diagnosis={'attack_probability': 0.02, 'predicted_attack_type': 'Normal'}
    )
    assert score_normal['overall_security_score'] > 80.0
    assert score_normal['leakage_analysis']['leakage_risk_tier'] == "MINIMAL_LEAKAGE"
    
    score_attack = analyzer.compute_security_score(
        metrics={'qber': 25.0, 'bell_parameter_s': 1.45, 'key_rate_kbps': 0.0},
        ml_diagnosis={'attack_probability': 0.99, 'predicted_attack_type': 'Intercept_Resend'}
    )
    assert score_attack['overall_security_score'] < 30.0
    assert score_attack['leakage_analysis']['leakage_risk_tier'] == "CRITICAL_LEAKAGE"

def test_adaptive_optimizer():
    from src.adaptive_optimizer import AdaptiveParameterOptimizer
    optimizer = AdaptiveParameterOptimizer()
    
    opt_normal = optimizer.optimize_parameters(
        metrics={'qber': 1.9, 'noise_level_cps': 850.0, 'distance_km': 25.0},
        ml_diagnosis={'attack_probability': 0.02, 'predicted_attack_type': 'Normal'}
    )
    assert opt_normal['optimal_p_z_basis'] == 0.85
    assert opt_normal['expected_sifting_efficiency_pct'] > 70.0
    assert opt_normal['anti_blinding_protection'] is False
    
    opt_blinding = optimizer.optimize_parameters(
        metrics={'qber': 0.25, 'noise_level_cps': 20.0, 'distance_km': 25.0},
        ml_diagnosis={'attack_probability': 0.98, 'predicted_attack_type': 'Detector_Blinding'}
    )
    assert opt_blinding['anti_blinding_protection'] is True
    assert opt_blinding['voa_attenuation_db'] == 15.0

if __name__ == '__main__':
    pytest.main(['-v', 'test_system.py'])
