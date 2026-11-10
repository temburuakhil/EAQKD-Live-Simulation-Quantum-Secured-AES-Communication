"""
Physics Channel Simulation for Entanglement-Assisted Quantum Key Distribution (EAQKD).
Models:
  - Bell state generation (|Phi+> = (|00> + |11>)/sqrt(2))
  - Optical fiber transmission (attenuation alpha = 0.20 dB/km at 1550 nm)
  - Detector quantum efficiency, dark count rate, and ambient noise
  - Projective quantum measurements in Rectilinear (Z) and Diagonal (X) bases
  - Propagation delay, timing jitter, and Bell inequality parameter (CHSH S)
"""

import numpy as np

class BellStateSource:
    """Simulates an SPDC source generating maximally entangled Bell pairs |Phi+>."""
    
    def __init__(self, rate_hz=1e6, fidelity=0.98, random_state=None):
        self.rate_hz = rate_hz
        self.fidelity = fidelity
        self.rng = np.random.RandomState(random_state)
        
    def generate_pairs(self, n_pairs=2048):
        """
        Generates n_pairs of entangled qubits.
        In the computational basis |Phi+>, Alice and Bob see identical random bits:
        both 0 with probability 0.5, or both 1 with probability 0.5.
        """
        raw_bits = self.rng.randint(0, 2, size=n_pairs)
        alice_bits = raw_bits.copy()
        bob_bits = raw_bits.copy()
        
        # Source imperfection: small depolarizing noise if fidelity < 1.0
        if self.fidelity < 1.0:
            error_mask = self.rng.rand(n_pairs) > self.fidelity
            bob_bits[error_mask] = 1 - bob_bits[error_mask]
            
        return alice_bits, bob_bits

class QuantumChannel:
    """
    Physical fiber-optic quantum channel linking Alice, Bob, and the Entangled Source.
    Computes realistic physical channel metrics.
    """
    
    def __init__(
        self,
        distance_km=25.0,
        fiber_loss_db_per_km=0.20,
        coupling_loss_db=1.8,
        dark_count_cps=850.0,
        detector_efficiency=0.25,
        source_rate_hz=1e6,
        random_state=None
    ):
        self.distance_km = float(distance_km)
        self.fiber_loss_db_per_km = float(fiber_loss_db_per_km)
        self.coupling_loss_db = float(coupling_loss_db)
        self.dark_count_cps = float(dark_count_cps)
        self.detector_efficiency = float(detector_efficiency)
        self.source_rate_hz = float(source_rate_hz)
        self.rng = np.random.RandomState(random_state)
        
    def calculate_metrics(self):
        """
        Calculates baseline channel physical telemetry metrics without attacks.
        Returns a dictionary of physical observables.
        """
        # Fiber attenuation
        photon_loss_db = (self.fiber_loss_db_per_km * self.distance_km) + self.coupling_loss_db
        transmittance = 10.0 ** (-photon_loss_db / 10.0)
        
        # Effective transmittance per arm
        effective_trans = self.detector_efficiency * np.sqrt(transmittance)
        
        # Noise level
        noise_cps = self.dark_count_cps + (self.distance_km * 1.5) + self.rng.normal(0, 30.0)
        noise_cps = max(50.0, noise_cps)
        p_dark = noise_cps / self.source_rate_hz
        
        # Optical baseline error (alignment, polarization drift)
        e_opt = 0.018 + self.rng.normal(0, 0.002)
        
        # Noise-induced error
        denom = 2.0 * (p_dark + effective_trans * (1.0 - p_dark) + 1e-12)
        e_noise = (p_dark * (1.0 - effective_trans)) / denom
        
        qber = np.clip((e_opt + e_noise) * 100.0, 0.8, 11.5)
        
        # Bell visibility and CHSH parameter S
        visibility = np.clip(1.0 - 2.0 * (qber / 100.0), 0.75, 0.995)
        bell_s = np.clip(2.0 * np.sqrt(2.0) * visibility, 2.05, 2.828)
        
        # Sifted key rate & Secret key rate
        sifted_rate = 0.5 * self.source_rate_hz * (effective_trans ** 2)
        
        p = np.clip(qber / 100.0, 1e-10, 0.5)
        h2 = -p * np.log2(p) - (1.0 - p) * np.log2(1.0 - p)
        # GLLP secret fraction formula
        secret_fraction = max(0.0, 1.0 - 2.2 * h2)
        key_rate_kbps = max(0.0, (sifted_rate * secret_fraction) / 1000.0)
        
        # Fiber delay & jitter
        delay_ns = 2.1 + (0.018 * self.distance_km) + self.rng.normal(0, 0.15)
        delay_ns = max(0.5, delay_ns)
        
        # Phase error rate
        phase_error = qber * (1.0 + self.rng.normal(0.02, 0.03))
        
        return {
            'distance_km': round(self.distance_km, 2),
            'photon_loss_db': round(photon_loss_db, 2),
            'noise_level_cps': round(noise_cps, 1),
            'qber': round(qber, 3),
            'key_rate_kbps': round(key_rate_kbps, 3),
            'delay_ns': round(delay_ns, 3),
            'visibility': round(visibility, 4),
            'bell_parameter_s': round(bell_s, 3),
            'phase_error_rate': round(phase_error, 3)
        }
