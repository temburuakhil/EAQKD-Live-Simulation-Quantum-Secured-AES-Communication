"""
Quantum Attack Threat Models for EAQKD Systems.
Implements:
  1. Intercept-Resend Attack (Eavesdropper measures and resends)
  2. Detector Blinding Attack (APD detector saturation into classical mode)
  3. Trojan Horse / Jamming Attack (Excess noise flooding / DoS)
  4. Photon Number Splitting (PNS) Attack (Multi-photon state exploitation)
"""

import numpy as np

class BaseAttack:
    """Base class for all quantum attacks."""
    def __init__(self, name="None", intensity=1.0):
        self.name = name
        self.intensity = float(np.clip(intensity, 0.0, 1.0))
        
    def perturb_channel(self, base_metrics: dict) -> dict:
        """Modifies the physical telemetry metrics according to the attack physics."""
        return base_metrics.copy()
        
    def perturb_qubits(self, alice_bits, bob_bits, alice_bases, bob_bases):
        """Modifies quantum bit streams if simulating discrete photon events."""
        return alice_bits, bob_bits

class InterceptResendAttack(BaseAttack):
    """
    Intercept-Resend Attack:
    Eve measures each photon in a randomly chosen basis (Z or X) and resends a replacement.
    Basis mismatch occurs 50% of the time, introducing a 25% error rate on intercepted bits.
    Violates Bell's inequality (CHSH S parameter drops <= 2.0).
    Adds electro-optical transceiver delay.
    """
    def __init__(self, intensity=0.85):
        super().__init__(name="Intercept_Resend", intensity=intensity)
        
    def perturb_channel(self, base_metrics: dict) -> dict:
        m = base_metrics.copy()
        dist = m['distance_km']
        
        # 25% error on intercepted fraction of qubits
        induced_qber = 25.0 * self.intensity
        m['qber'] = round(min(35.0, m['qber'] + induced_qber + np.random.normal(0, 0.5)), 3)
        
        # Bell visibility collapses
        m['visibility'] = round(float(np.clip(1.0 - 2.0 * (m['qber'] / 100.0), 0.35, 0.70)), 4)
        m['bell_parameter_s'] = round(float(np.clip(2.0 * np.sqrt(2.0) * m['visibility'], 1.10, 1.98)), 3)
        
        # Key rate is zeroed out because QBER exceeds security threshold
        m['key_rate_kbps'] = 0.0
        
        # Eve's hardware detection and laser resend latency
        eve_delay = 2.2 * self.intensity
        m['delay_ns'] = round(m['delay_ns'] + eve_delay, 3)
        m['phase_error_rate'] = round(min(38.0, m['qber'] * 1.05), 3)
        
        return m

    def perturb_qubits(self, alice_bits, bob_bits, alice_bases, bob_bases):
        n = len(bob_bits)
        eve_bases = np.random.randint(0, 2, size=n)
        attack_mask = np.random.rand(n) < self.intensity
        
        # Where Eve attacked and basis differed from Alice, outcome is randomized (50% error)
        mismatch = (eve_bases != alice_bases) & attack_mask
        flip = np.random.rand(n) < 0.5
        bob_bits[mismatch & flip] = 1 - bob_bits[mismatch & flip]
        return alice_bits, bob_bits

class DetectorBlindingAttack(BaseAttack):
    """
    Detector Blinding Attack:
    Eve illuminates Bob's APD detectors with continuous-wave (CW) laser light,
    forcing them into classical threshold conduction mode.
    Effect: Noise level (dark counts) drops near zero, QBER appears artificially tiny,
    and timing jitter collapses.
    """
    def __init__(self, intensity=0.90):
        super().__init__(name="Detector_Blinding", intensity=intensity)
        
    def perturb_channel(self, base_metrics: dict) -> dict:
        m = base_metrics.copy()
        # Dark counts drop unnaturally low
        m['noise_level_cps'] = round(float(np.random.uniform(5.0, 60.0)), 1)
        # QBER appears artificially suppressed
        m['qber'] = round(float(np.random.uniform(0.08, 0.65)), 3)
        m['visibility'] = round(float(np.random.uniform(0.98, 0.999)), 4)
        m['bell_parameter_s'] = round(float(np.random.uniform(2.76, 2.828)), 3)
        # Timing jitter collapses because detector is triggered deterministically
        m['delay_ns'] = round(float(np.random.uniform(0.45, 1.15)), 3)
        m['phase_error_rate'] = round(m['qber'] * 1.02, 3)
        m['key_rate_kbps'] = round(float(np.random.uniform(10.0, 24.0)), 3)
        return m

class JammingAttack(BaseAttack):
    """
    Trojan Horse / Channel Jamming Attack:
    Eve injects high-intensity broadband optical pulses or probe lasers into the fiber,
    generating severe background noise, high QBER, and massive timing jitter.
    """
    def __init__(self, intensity=0.85):
        super().__init__(name="Jamming_DoS", intensity=intensity)
        
    def perturb_channel(self, base_metrics: dict) -> dict:
        m = base_metrics.copy()
        # Massive noise injection
        m['noise_level_cps'] = round(float(np.random.uniform(20000.0, 75000.0) * self.intensity), 1)
        m['qber'] = round(float(np.random.uniform(14.0, 32.0)), 3)
        m['visibility'] = round(float(np.clip(1.0 - 2.0 * (m['qber'] / 100.0), 0.30, 0.70)), 4)
        m['bell_parameter_s'] = round(float(np.clip(2.0 * np.sqrt(2.0) * m['visibility'], 0.90, 1.95)), 3)
        m['key_rate_kbps'] = round(float(np.random.uniform(0.0, 0.02)), 3)
        m['delay_ns'] = round(float(np.random.uniform(7.0, 16.0)), 3)
        m['phase_error_rate'] = round(float(m['qber'] * 1.15), 3)
        return m

class PNSAttack(BaseAttack):
    """
    Photon Number Splitting (PNS) Attack:
    Eve selectively intercepts multi-photon pulses, taps one photon, and routes the remainder
    through an engineered low-loss superconducting or vacuum channel.
    Effect: Measured photon loss is anomalously low for the given fiber distance, while QBER
    remains deceptively normal.
    """
    def __init__(self, intensity=0.80):
        super().__init__(name="PNS", intensity=intensity)
        
    def perturb_channel(self, base_metrics: dict) -> dict:
        m = base_metrics.copy()
        dist = m['distance_km']
        expected_loss = 0.20 * dist + 1.8
        
        # Loss is reduced below natural physics by Eve's channel replacement
        loss_reduction = float(np.random.uniform(5.0, 11.0) * self.intensity)
        m['photon_loss_db'] = round(max(1.2, expected_loss - loss_reduction), 2)
        
        # QBER stays deceptively low to evade naive fixed-threshold QBER detectors
        m['qber'] = round(float(np.random.uniform(3.5, 7.5)), 3)
        m['visibility'] = round(float(np.random.uniform(0.86, 0.93)), 4)
        m['bell_parameter_s'] = round(float(np.random.uniform(2.38, 2.62)), 3)
        m['key_rate_kbps'] = round(float(np.random.uniform(0.3, 1.4)), 3)
        m['delay_ns'] = round(float(2.0 + (0.016 * dist) - 0.4), 3)
        m['phase_error_rate'] = round(float(m['qber'] * 1.2), 3)
        return m
