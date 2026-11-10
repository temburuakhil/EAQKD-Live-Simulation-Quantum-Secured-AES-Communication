"""
Command-Line Demonstration of the EAQKD + ML Attack Detection + AES System.
Demonstrates:
  - Normal EAQKD key distribution + AES-256-GCM encryption & decryption
  - Detection and defense against Intercept-Resend Attack
  - Detection and defense against Detector Blinding Attack
  - Detection and defense against Jamming / DoS Attack
  - Detection and defense against Photon Number Splitting (PNS) Attack
  - Custom telemetry inference testing
"""

import sys
import json
from src.pipeline import EAQKDSecureSystem

def print_separator(title=""):
    print("\n" + "=" * 70)
    if title:
        print(f"  {title}")
        print("=" * 70)

def display_session_result(res: dict):
    m = res['channel_telemetry']
    print(f"Channel Parameters (Distance: {res['distance_km']} km):")
    print(f"  - QBER:            {m['qber']:.3f}%")
    print(f"  - Photon Loss:     {m['photon_loss_db']:.2f} dB")
    print(f"  - Noise Level:     {m['noise_level_cps']:.1f} cps")
    print(f"  - Key Rate:        {m['key_rate_kbps']:.3f} kbps")
    print(f"  - Delay:           {m['delay_ns']:.3f} ns")
    print(f"  - Bell CHSH S:     {m.get('bell_parameter_s', 'N/A')}")
    
    print("\nMachine Learning Security Guard (XGBoost):")
    print(f"  - Attack Probability: {res['ml_attack_probability']*100:.2f}%")
    print(f"  - Threat Level:       {res['ml_threat_level']}")
    print(f"  - Classified Attack:  {res['ml_detected_attack_type']}")
    print(f"  - Security Action:    {res['ml_security_action']}")
    print(f"  - Status Message:     {res['ml_status_message']}")

    # Security Score and Leakage Analysis
    sec = res.get('security_score', {})
    if sec:
        leak = sec.get('leakage_analysis', {})
        print("\nQuantum Security Score & Leakage Analysis:")
        print(f"  - Overall Score:      {sec.get('overall_security_score', 0):.1f}/100 ({sec.get('rating', '')})")
        print(f"  - Leakage Risk Tier:  {leak.get('leakage_risk_tier', 'N/A')}")
        print(f"  - Eve Holevo Bound:   {leak.get('eve_information_upper_bound_bits', 0):.4f} bits/photon")

    # Adaptive Optimizations
    adapt = res.get('adaptive_optimization', {})
    if adapt:
        print("\nAdaptive Parameter Optimizations:")
        print(f"  - Optimal Basis:      p_Z={adapt.get('optimal_p_z_basis', 0.5):.2f}, p_X={adapt.get('optimal_p_x_basis', 0.5):.2f}")
        print(f"  - Sifting Efficiency: {adapt.get('expected_sifting_efficiency_pct', 50):.1f}%")
        print(f"  - Coincidence Window: {adapt.get('optimal_coincidence_window_ns', 2.5):.1f} ns")
        print(f"  - Anti-Blinding VOA:  {'ENGAGED' if adapt.get('anti_blinding_protection') else 'Disengaged'}")
    
    print("\nCryptographic Outcome:")
    if res['key_distribution_success']:
        print("  - EAQKD Status:       [SUCCESS] 256-bit symmetric key established.")
        print(f"  - Quantum Key Hex:    {res['quantum_key_hex'][:24]}...{res['quantum_key_hex'][-8:]}")
        print(f"  - Key Fingerprint:    {res['key_fingerprint']}")
        aes = res['aes_encryption']
        print(f"  - Plaintext Message:  \"{aes['plaintext']}\"")
        print(f"  - AES Ciphertext Hex: {aes['ciphertext_hex'][:40]}... (AES-256-GCM)")
        print(f"  - Nonce (IV):         {aes['nonce_hex']}")
        print(f"  - Decrypted at Bob:   \"{aes['decrypted_plaintext']}\"")
        print(f"  - Integrity Verified: {aes['authentication_verified']} (128-bit MAC Tag Match)")
    else:
        print("  - EAQKD Status:       [ABORTED] Quantum channel flagged as unsafe!")
        print(f"  - Reason:             {res['abort_reason']}")
        print("  - AES Protection:     Message transmission blocked. Zero secret leakage.")

def main():
    print_separator("EAQKD System with XGBoost Attack Detection & AES-256 Encryption")
    print("Initializing Quantum Optical Simulation and Machine Learning Models...")
    
    system = EAQKDSecureSystem(attack_threshold=0.50, max_tolerable_qber=11.0)
    secret_payload = "CONFIDENTIAL: Quantum Key Established Successfully. Proceed with Secure Comms."

    # Scenario 1: Clean Channel (Normal Operation)
    print_separator("SCENARIO 1: Normal Channel Operation (No Attack)")
    res1 = system.run_secure_session(
        message=secret_payload,
        distance_km=25.0,
        attack_type="None"
    )
    display_session_result(res1)

    # Scenario 2: Intercept-Resend Attack
    print_separator("SCENARIO 2: Under Intercept-Resend Attack (Eve Active)")
    res2 = system.run_secure_session(
        message=secret_payload,
        distance_km=45.0,
        attack_type="Intercept_Resend",
        attack_intensity=0.90
    )
    display_session_result(res2)

    # Scenario 3: Detector Blinding Attack
    print_separator("SCENARIO 3: Under Detector Blinding Attack (CW Laser Saturation)")
    res3 = system.run_secure_session(
        message=secret_payload,
        distance_km=30.0,
        attack_type="Detector_Blinding",
        attack_intensity=0.95
    )
    display_session_result(res3)

    # Scenario 4: Trojan Horse / Jamming Attack
    print_separator("SCENARIO 4: Under Trojan Horse / Jamming Attack (High-Power Noise)")
    res4 = system.run_secure_session(
        message=secret_payload,
        distance_km=50.0,
        attack_type="Jamming_DoS",
        attack_intensity=0.85
    )
    display_session_result(res4)

    # Scenario 5: Photon Number Splitting (PNS) Attack
    print_separator("SCENARIO 5: Under Photon Number Splitting (PNS) Attack")
    res5 = system.run_secure_session(
        message=secret_payload,
        distance_km=75.0,
        attack_type="PNS",
        attack_intensity=0.85
    )
    display_session_result(res5)

    # Scenario 6: Manual Telemetry Diagnostic Evaluation
    print_separator("SCENARIO 6: Custom Telemetry Diagnostic Query")
    test_metrics = {
        'qber': 21.5,
        'photon_loss_db': 12.0,
        'noise_level_cps': 920.0,
        'distance_km': 50.0,
        'key_rate_kbps': 0.0,
        'delay_ns': 5.2
    }
    print(f"Querying ML Detector with custom inputs: {test_metrics}")
    diag = system.evaluate_custom_telemetry(**test_metrics)
    print(f"ML Attack Probability: {diag['attack_probability']*100:.2f}%")
    print(f"Detected Attack Type:  {diag['predicted_attack_type']}")
    print(f"Security Action:       {diag['security_action']}")
    print(f"Class Probabilities:   {json.dumps(diag['class_probabilities'], indent=2)}")

    print_separator("End-to-End EAQKD Demonstration Completed Successfully")

if __name__ == '__main__':
    main()
