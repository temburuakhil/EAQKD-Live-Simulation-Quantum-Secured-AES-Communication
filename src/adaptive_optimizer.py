"""
Adaptive Parameter Optimizer for EAQKD System.
Implements:
  1. Dynamic Asymmetric Basis Selection (p_Z vs p_X tuning to boost throughput)
  2. Coincidence Time Window Optimization (suppresses noise-induced QBER)
  3. Active Anti-Blinding Attenuation Defense
  4. Dynamic Error Correction (reconciliation block size scaling)
"""

import numpy as np

class AdaptiveParameterOptimizer:
    """Dynamically tunes quantum transmission parameters to maximize throughput and resilience."""

    def __init__(self):
        # Default baseline configuration
        self.default_p_basis = 0.50          # 50% Z, 50% X
        self.default_coinc_window_ns = 2.50  # ns
        self.default_voa_attenuation_db = 0.0  # dB

    def optimize_parameters(self, metrics: dict, ml_diagnosis: dict) -> dict:
        """
        Analyzes current channel conditions and ML threat levels to recommend/apply
        optimal parameter adaptations.
        """
        qber = float(metrics.get('qber', 2.0))
        noise = float(metrics.get('noise_level_cps', 850.0))
        dist = float(metrics.get('distance_km', 25.0))
        attack_prob = float(ml_diagnosis.get('attack_probability', 0.0))
        attack_type = ml_diagnosis.get('predicted_attack_type', 'Normal')

        adaptations = []

        # -------------------------------------------------------------
        # 1. Asymmetric Basis Selection (Mohamed & Al-Kuwari 2026)
        # -------------------------------------------------------------
        if attack_prob < 0.15 and qber < 5.0:
            # Clean channel: aggressively bias towards Z basis for higher key rate
            p_z = 0.85
            p_x = 0.15
            sifting_eff = (p_z ** 2) + (p_x ** 2)  # ~ 74.5% sifting throughput!
            adaptations.append("Asymmetric Basis Optimization enabled (85% Z, 15% X): Sifting efficiency increased from 50% to 74.5%.")
        elif attack_prob < 0.40:
            # Mild noise: moderate bias
            p_z = 0.70
            p_x = 0.30
            sifting_eff = (p_z ** 2) + (p_x ** 2)
            adaptations.append("Moderate Asymmetric Basis enabled (70% Z, 30% X) to balance key rate with security testing.")
        else:
            # Threat or elevated noise: symmetric basis for rigorous Bell/security testing
            p_z = 0.50
            p_x = 0.50
            sifting_eff = 0.50
            adaptations.append("Symmetric Basis forced (50% Z, 50% X) for maximum security verification.")

        # -------------------------------------------------------------
        # 2. Coincidence Time Window Tuning (Noise Filtering)
        # -------------------------------------------------------------
        if noise > 1500.0 or dist > 60.0:
            # High noise: narrow the coincidence window to reject uncorrelated dark counts
            coinc_window_ns = 1.2
            noise_reduction_pct = 45.0
            adaptations.append(f"High background noise detected ({noise:.0f} cps): Coincidence window narrowed to 1.2 ns (suppressing ~45% noise counts).")
        else:
            coinc_window_ns = 2.5
            noise_reduction_pct = 0.0

        # -------------------------------------------------------------
        # 3. Active Anti-Blinding Shutter / VOA Countermeasure
        # -------------------------------------------------------------
        if attack_type == "Detector_Blinding" or (qber < 0.8 and noise < 100.0):
            voa_attenuation_db = 15.0
            anti_blinding_active = True
            adaptations.append("ANTI-BLINDING COUNTERMEASURE TRIGGERED: Variable Optical Attenuator (+15 dB) engaged to force APD back into Geiger mode.")
        else:
            voa_attenuation_db = 0.0
            anti_blinding_active = False

        # -------------------------------------------------------------
        # 4. Error Correction Block Size Optimization
        # -------------------------------------------------------------
        if qber < 2.0:
            ec_block_size = 128
            ec_efficiency = 1.08
        elif qber < 5.0:
            ec_block_size = 64
            ec_efficiency = 1.15
        else:
            ec_block_size = 32
            ec_efficiency = 1.25

        return {
            'optimal_p_z_basis': round(p_z, 2),
            'optimal_p_x_basis': round(p_x, 2),
            'expected_sifting_efficiency_pct': round(sifting_eff * 100.0, 1),
            'optimal_coincidence_window_ns': coinc_window_ns,
            'noise_reduction_factor_pct': noise_reduction_pct,
            'anti_blinding_protection': anti_blinding_active,
            'voa_attenuation_db': voa_attenuation_db,
            'recommended_ec_block_size': ec_block_size,
            'ec_efficiency_f': ec_efficiency,
            'adaptations_applied': adaptations
        }
