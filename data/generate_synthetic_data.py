"""
Synthetic Dataset Generator for EAQKD (Entanglement-Assisted Quantum Key Distribution)
Physics-grounded quantum channel simulation modeling optical fiber attenuation,
detector noise, propagation delay, and quantum attacks:
  - Normal Operation (Class 0: Normal)
  - Intercept-Resend Attack (Class 1: Intercept_Resend)
  - Detector Blinding Attack (Class 2: Detector_Blinding)
  - Trojan Horse / Jamming Attack (Class 3: Jamming_DoS)
  - Photon Number Splitting Attack (Class 4: PNS)

Features generated:
  - distance_km: Transmission link distance (1 to 150 km)
  - photon_loss_db: Channel attenuation in dB (alpha * d + coupling loss)
  - noise_level_cps: Background noise and dark count rate (counts per second)
  - qber: Quantum Bit Error Rate (%)
  - key_rate_kbps: Secret key generation rate (kbps)
  - delay_ns: Coincidence matching window delay / jitter (ns)
  - visibility: Bell state quantum interference visibility (0 to 1)
  - bell_parameter_s: CHSH parameter S (classical limit = 2.0, max quantum = 2.828)
  - phase_error_rate: Phase error rate e_x (%)

Targets:
  - attack_detected: Binary (0 = Normal, 1 = Attack)
  - attack_type: Multi-class string name
"""

import numpy as np
import pandas as pd
import os

def shannon_entropy(p):
    """Binary Shannon entropy h2(p)."""
    p = np.clip(p, 1e-12, 1.0 - 1e-12)
    return -p * np.log2(p) - (1.0 - p) * np.log2(1.0 - p)

def generate_eaqkd_dataset(n_samples=15000, random_seed=42):
    np.random.seed(random_seed)
    
    # 50% Normal, 50% Attacks distributed across 4 attack categories
    n_normal = n_samples // 2
    n_per_attack = (n_samples - n_normal) // 4
    n_attacks_total = n_per_attack * 4
    total_records = n_normal + n_attacks_total

    # Source parameters
    R_source = 1e6  # 1 MHz Bell state pair generation rate (10^6 pairs/sec)
    alpha_fiber = 0.20  # Standard single-mode fiber loss (dB/km at 1550 nm)
    eta_det = 0.25  # Detector quantum efficiency (25%)
    
    records = []

    # -------------------------------------------------------------
    # 1. NORMAL SAMPLES (No Attack)
    # -------------------------------------------------------------
    for _ in range(n_normal):
        dist = np.random.uniform(1.0, 140.0)  # km
        coupling_loss = np.random.normal(1.8, 0.3)  # dB
        coupling_loss = max(0.5, coupling_loss)
        
        # Standard fiber loss
        photon_loss = alpha_fiber * dist + coupling_loss  # dB
        transmittance = 10 ** (-photon_loss / 10.0)
        
        # Environmental / detector noise
        noise_cps = np.random.normal(850.0, 180.0) + (dist * 1.5)
        noise_cps = max(100.0, noise_cps)
        p_dark = noise_cps / R_source
        
        # Optical baseline error
        e_opt = np.random.normal(0.018, 0.003)  # 1.8% baseline optical misalignment
        
        # Noise-induced error
        effective_trans = eta_det * np.sqrt(transmittance)
        e_noise = (p_dark * (1 - effective_trans)) / (2 * (p_dark + effective_trans * (1 - p_dark) + 1e-12))
        
        qber = np.clip((e_opt + e_noise) * 100.0 + np.random.normal(0, 0.25), 0.8, 9.5)
        
        # Visibility and Bell parameter S
        visibility = np.clip(1.0 - 2.0 * (qber / 100.0) + np.random.normal(0, 0.01), 0.78, 0.99)
        bell_s = np.clip(2.0 * np.sqrt(2.0) * visibility, 2.15, 2.82)
        
        # Key Rate (sifted & secret key rate)
        sifted_rate = 0.5 * R_source * (effective_trans ** 2)
        h2 = shannon_entropy(qber / 100.0)
        secret_fraction = max(0.0, 1.0 - 2.2 * h2)  # accounting for error correction efficiency
        key_rate_kbps = max(0.01, (sifted_rate * secret_fraction) / 1000.0)
        
        # Delay (jitter + dispersion over fiber)
        delay_ns = 2.1 + (0.018 * dist) + np.random.normal(0, 0.25)
        delay_ns = max(1.0, delay_ns)
        
        # Phase error rate (close to qber in unattacked channel)
        phase_error = np.clip(qber * np.random.normal(1.02, 0.04), 0.8, 10.5)

        records.append({
            'distance_km': round(dist, 2),
            'photon_loss_db': round(photon_loss, 2),
            'noise_level_cps': round(noise_cps, 1),
            'qber': round(qber, 3),
            'key_rate_kbps': round(key_rate_kbps, 3),
            'delay_ns': round(delay_ns, 3),
            'visibility': round(visibility, 4),
            'bell_parameter_s': round(bell_s, 3),
            'phase_error_rate': round(phase_error, 3),
            'attack_detected': 0,
            'attack_type': 'Normal'
        })

    # -------------------------------------------------------------
    # 2. INTERCEPT-RESEND ATTACK (Class 1)
    # -------------------------------------------------------------
    for _ in range(n_per_attack):
        dist = np.random.uniform(5.0, 140.0)
        coupling_loss = np.random.normal(1.9, 0.4)
        photon_loss = alpha_fiber * dist + coupling_loss
        transmittance = 10 ** (-photon_loss / 10.0)
        
        # Eve intercepts a fraction f_eve of the entangled photons
        f_eve = np.random.uniform(0.5, 1.0)
        
        # Theoretical error: 25% error on intercepted bits due to basis mismatch
        base_qber = 2.0 + (dist * 0.04)
        qber = base_qber + (25.0 * f_eve) + np.random.normal(0, 1.2)
        qber = np.clip(qber, 14.5, 34.0)
        
        # Bell inequality violation collapses
        visibility = np.clip(1.0 - 2.0 * (qber / 100.0) + np.random.normal(0, 0.02), 0.35, 0.70)
        bell_s = np.clip(2.0 * np.sqrt(2.0) * visibility, 1.10, 1.98)  # Classical limit <= 2.0!
        
        noise_cps = np.random.normal(950.0, 220.0) + (dist * 1.8)
        
        # Key rate drops to 0 because QBER > 11% threshold
        key_rate_kbps = 0.0
        
        # Delay increases due to Eve's intercept-measure-resend hardware delay
        eve_hw_delay = np.random.uniform(1.8, 4.2)
        delay_ns = 2.1 + (0.018 * dist) + eve_hw_delay + np.random.normal(0, 0.3)
        
        phase_error = np.clip(qber * np.random.normal(1.05, 0.06), 14.0, 36.0)

        records.append({
            'distance_km': round(dist, 2),
            'photon_loss_db': round(photon_loss, 2),
            'noise_level_cps': round(noise_cps, 1),
            'qber': round(qber, 3),
            'key_rate_kbps': round(key_rate_kbps, 3),
            'delay_ns': round(delay_ns, 3),
            'visibility': round(visibility, 4),
            'bell_parameter_s': round(bell_s, 3),
            'phase_error_rate': round(phase_error, 3),
            'attack_detected': 1,
            'attack_type': 'Intercept_Resend'
        })

    # -------------------------------------------------------------
    # 3. DETECTOR BLINDING ATTACK (Class 2)
    # -------------------------------------------------------------
    for _ in range(n_per_attack):
        dist = np.random.uniform(2.0, 130.0)
        coupling_loss = np.random.normal(1.8, 0.3)
        photon_loss = alpha_fiber * dist + coupling_loss
        
        # Detectors are blinded by CW light into linear regime
        # Noise (dark counts) drops unnaturally low to near zero
        noise_cps = np.random.uniform(5.0, 75.0)
        
        # QBER becomes unnaturally small or pegged to zero
        qber = np.random.uniform(0.05, 0.75)
        
        visibility = np.random.uniform(0.97, 0.999)
        bell_s = np.random.uniform(2.75, 2.828)
        
        # Apparent key rate is anomalous (fixed or inflated)
        key_rate_kbps = np.random.uniform(8.0, 25.0)
        
        # Timing jitter collapses because detector is triggered by deterministic pulses
        delay_ns = np.random.uniform(0.4, 1.2)
        phase_error = np.random.uniform(0.05, 0.8)

        records.append({
            'distance_km': round(dist, 2),
            'photon_loss_db': round(photon_loss, 2),
            'noise_level_cps': round(noise_cps, 1),
            'qber': round(qber, 3),
            'key_rate_kbps': round(key_rate_kbps, 3),
            'delay_ns': round(delay_ns, 3),
            'visibility': round(visibility, 4),
            'bell_parameter_s': round(bell_s, 3),
            'phase_error_rate': round(phase_error, 3),
            'attack_detected': 1,
            'attack_type': 'Detector_Blinding'
        })

    # -------------------------------------------------------------
    # 4. TROJAN HORSE / CHANNEL JAMMING ATTACK (Class 3)
    # -------------------------------------------------------------
    for _ in range(n_per_attack):
        dist = np.random.uniform(5.0, 140.0)
        coupling_loss = np.random.normal(2.2, 0.6)
        photon_loss = alpha_fiber * dist + coupling_loss + np.random.uniform(2.0, 6.0)
        
        # Massive noise injection from bright optical probe pulses / flooding
        noise_cps = np.random.uniform(15000.0, 85000.0)
        
        # QBER increases significantly due to high stray count rate
        qber = np.random.uniform(12.0, 36.0)
        
        visibility = np.clip(1.0 - 2.0 * (qber / 100.0), 0.25, 0.72)
        bell_s = np.clip(2.0 * np.sqrt(2.0) * visibility, 0.8, 1.95)
        
        # Key rate collapses
        key_rate_kbps = np.random.uniform(0.0, 0.05)
        
        # Delay jitter broadens massively
        delay_ns = np.random.uniform(6.5, 17.5)
        phase_error = np.clip(qber * np.random.normal(1.15, 0.1), 12.0, 42.0)

        records.append({
            'distance_km': round(dist, 2),
            'photon_loss_db': round(photon_loss, 2),
            'noise_level_cps': round(noise_cps, 1),
            'qber': round(qber, 3),
            'key_rate_kbps': round(key_rate_kbps, 3),
            'delay_ns': round(delay_ns, 3),
            'visibility': round(visibility, 4),
            'bell_parameter_s': round(bell_s, 3),
            'phase_error_rate': round(phase_error, 3),
            'attack_detected': 1,
            'attack_type': 'Jamming_DoS'
        })

    # -------------------------------------------------------------
    # 5. PHOTON NUMBER SPLITTING (PNS) ATTACK (Class 4)
    # -------------------------------------------------------------
    for _ in range(n_per_attack):
        dist = np.random.uniform(30.0, 150.0)  # PNS is typically executed over medium to long distances
        expected_loss = alpha_fiber * dist + 1.8
        
        # Eve replaces fiber with lossless/low-loss channel, suppressing apparent attenuation
        stolen_loss_reduction = np.random.uniform(4.0, 12.0)
        photon_loss = max(1.0, expected_loss - stolen_loss_reduction)
        
        noise_cps = np.random.normal(800.0, 150.0)
        
        # QBER stays relatively low to evade simple threshold detectors!
        qber = np.random.uniform(3.2, 7.8)
        
        visibility = np.random.uniform(0.85, 0.94)
        bell_s = np.random.uniform(2.35, 2.65)
        
        # Key rate appears inconsistent with distance/loss profile
        key_rate_kbps = np.random.uniform(0.2, 1.5)
        
        delay_ns = 2.1 + (0.018 * dist) + np.random.normal(-0.5, 0.3)
        phase_error = np.clip(qber * np.random.normal(1.2, 0.08), 3.5, 9.8)

        records.append({
            'distance_km': round(dist, 2),
            'photon_loss_db': round(photon_loss, 2),
            'noise_level_cps': round(noise_cps, 1),
            'qber': round(qber, 3),
            'key_rate_kbps': round(key_rate_kbps, 3),
            'delay_ns': round(delay_ns, 3),
            'visibility': round(visibility, 4),
            'bell_parameter_s': round(bell_s, 3),
            'phase_error_rate': round(phase_error, 3),
            'attack_detected': 1,
            'attack_type': 'PNS'
        })

    df = pd.DataFrame(records)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    return df

if __name__ == '__main__':
    df = generate_eaqkd_dataset(n_samples=15000, random_seed=42)
    output_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(output_dir, 'eaqkd_attack_dataset.csv')
    df.to_csv(output_path, index=False)
    print(f"Generated synthetic EAQKD dataset: {df.shape[0]} rows, {df.shape[1]} columns")
    print(f"Saved to: {output_path}")
    print("\nClass distribution (attack_type):")
    print(df['attack_type'].value_counts())
    print("\nBinary label distribution (attack_detected):")
    print(df['attack_detected'].value_counts(normalize=True))
    print("\nDataset Summary Statistics:")
    print(df.describe().T[['mean', 'std', 'min', 'max']])
