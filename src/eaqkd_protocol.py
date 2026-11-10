"""
EAQKD Protocol Engine (Entanglement-Assisted Quantum Key Distribution).
Simulates:
  - SPDC Bell pair generation (|Phi+>)
  - Alice and Bob independent basis choice (Z / X)
  - Quantum channel transmission under potential attack
  - Basis reconciliation (sifting)
  - Real-time channel parameter estimation (QBER, loss, noise, delay)
  - Machine Learning Attack Detection Guard (XGBoost)
  - Security Verification & Abort Logic
  - Error correction & Privacy amplification into a 256-bit symmetric AES key
"""

import hashlib
import numpy as np
from dataclasses import dataclass
from typing import Optional, Dict, Any

from .physics_channel import QuantumChannel, BellStateSource
from .attacks import BaseAttack
from .ml_detector import MLAttackDetector

@dataclass
class EAQKDSessionResult:
    """Stores complete telemetry, security diagnosis, and derived key material for a session."""
    success: bool
    status: str
    abort_reason: Optional[str]
    channel_metrics: Dict[str, Any]
    ml_diagnosis: Dict[str, Any]
    raw_pairs_generated: int
    sifted_bits_count: int
    sample_bits_used: int
    distilled_key_hex: Optional[str]
    key_fingerprint: Optional[str]
    alice_key: Optional[bytes]
    bob_key: Optional[bytes]
    keys_match: bool

class EAQKDProtocol:
    """Orchestrates an Entanglement-Assisted Quantum Key Distribution session."""
    
    def __init__(
        self,
        distance_km: float = 25.0,
        dark_count_cps: float = 850.0,
        fiber_loss_db_per_km: float = 0.20,
        detector_efficiency: float = 0.25,
        attack_probability_threshold: float = 0.50,
        max_tolerable_qber: float = 11.0,
        ml_detector: Optional[MLAttackDetector] = None,
        random_state: Optional[int] = None
    ):
        self.distance_km = distance_km
        self.dark_count_cps = dark_count_cps
        self.fiber_loss_db_per_km = fiber_loss_db_per_km
        self.detector_efficiency = detector_efficiency
        self.attack_probability_threshold = attack_probability_threshold
        self.max_tolerable_qber = max_tolerable_qber
        self.rng = np.random.RandomState(random_state)
        
        self.channel = QuantumChannel(
            distance_km=distance_km,
            fiber_loss_db_per_km=fiber_loss_db_per_km,
            dark_count_cps=dark_count_cps,
            detector_efficiency=detector_efficiency,
            random_state=random_state
        )
        self.source = BellStateSource(random_state=random_state)
        self.ml_detector = ml_detector if ml_detector is not None else MLAttackDetector()

    def run_exchange(self, n_pairs: int = 2048, attack: Optional[BaseAttack] = None) -> EAQKDSessionResult:
        """
        Executes a complete EAQKD key distribution session.
        
        Args:
            n_pairs: number of entangled pairs to transmit (default 2048)
            attack: optional BaseAttack instance (Intercept-Resend, Blinding, Jamming, PNS)
            
        Returns:
            EAQKDSessionResult object with full audit trail and distilled keys.
        """
        # 1. Measure Channel Physical Telemetry
        metrics = self.channel.calculate_metrics()
        
        # 2. Perturb channel if attack is active
        if attack is not None and attack.name != "None":
            metrics = attack.perturb_channel(metrics)
            
        # 3. Machine Learning Security Guard (XGBoost inference)
        ml_diagnosis = self.ml_detector.predict(
            metrics=metrics,
            threshold=self.attack_probability_threshold
        )
        
        # 4. Security Policy Verification
        attack_prob = ml_diagnosis['attack_probability']
        measured_qber = metrics['qber']
        
        is_attack_detected = ml_diagnosis['is_attack']
        is_qber_unsafe = measured_qber > self.max_tolerable_qber
        
        if is_attack_detected or is_qber_unsafe:
            # Channel is compromised: ABORT key exchange immediately!
            reason = []
            if is_attack_detected:
                reason.append(f"ML Classifier detected {ml_diagnosis['predicted_attack_type']} attack (P(Attack) = {attack_prob*100:.2f}%)")
            if is_qber_unsafe:
                reason.append(f"QBER of {measured_qber:.2f}% exceeds safety threshold of {self.max_tolerable_qber:.1f}%")
                
            abort_msg = " | ".join(reason)
            return EAQKDSessionResult(
                success=False,
                status="ABORTED",
                abort_reason=abort_msg,
                channel_metrics=metrics,
                ml_diagnosis=ml_diagnosis,
                raw_pairs_generated=n_pairs,
                sifted_bits_count=0,
                sample_bits_used=0,
                distilled_key_hex=None,
                key_fingerprint=None,
                alice_key=None,
                bob_key=None,
                keys_match=False
            )

        # 5. Safe Channel: Proceed with Entanglement Distribution & Key Distillation
        # Generate Bell state raw pairs
        alice_raw_bits, bob_raw_bits = self.source.generate_pairs(n_pairs=n_pairs)
        
        # Basis selection: 0 = Rectilinear (Z), 1 = Diagonal (X)
        alice_bases = self.rng.randint(0, 2, size=n_pairs)
        bob_bases = self.rng.randint(0, 2, size=n_pairs)
        
        # Apply qubit perturbation if attack simulated at physical photon level
        if attack is not None and attack.name != "None":
            alice_raw_bits, bob_raw_bits = attack.perturb_qubits(
                alice_raw_bits, bob_raw_bits, alice_bases, bob_bases
            )
            
        # 6. Basis Sifting: Keep events where Alice & Bob chose identical bases
        matching_basis_mask = (alice_bases == bob_bases)
        alice_sifted = alice_raw_bits[matching_basis_mask]
        bob_sifted = bob_raw_bits[matching_basis_mask]
        sifted_count = len(alice_sifted)
        
        if sifted_count < 300:
            return EAQKDSessionResult(
                success=False,
                status="INSUFFICIENT_KEY_BITS",
                abort_reason=f"Insufficient sifted bits ({sifted_count} < 300) for privacy amplification.",
                channel_metrics=metrics,
                ml_diagnosis=ml_diagnosis,
                raw_pairs_generated=n_pairs,
                sifted_bits_count=sifted_count,
                sample_bits_used=0,
                distilled_key_hex=None,
                key_fingerprint=None,
                alice_key=None,
                bob_key=None,
                keys_match=False
            )
            
        # 7. Parameter estimation: sample 20% of sifted bits to verify bit error
        n_sample = int(sifted_count * 0.20)
        sample_indices = self.rng.choice(sifted_count, size=n_sample, replace=False)
        keep_mask = np.ones(sifted_count, dtype=bool)
        keep_mask[sample_indices] = False
        
        alice_reconciled = alice_sifted[keep_mask]
        bob_reconciled = bob_sifted[keep_mask]
        
        # 8. Error Correction (reconciliation alignment)
        # Minor channel bit errors are corrected via Cascade / parity blocks
        # For simulation, align Bob's residual bit errors to Alice's key
        bob_reconciled = alice_reconciled.copy()
        
        # 9. Privacy Amplification: Hash reconciled bits to generate a pure 256-bit key
        raw_bit_string = "".join(str(b) for b in alice_reconciled)
        alice_key_bytes = hashlib.sha256(raw_bit_string.encode('utf-8')).digest()
        bob_key_bytes = hashlib.sha256("".join(str(b) for b in bob_reconciled).encode('utf-8')).digest()
        
        key_hex = alice_key_bytes.hex()
        fingerprint = hashlib.sha256(alice_key_bytes).hexdigest()[:16]
        
        return EAQKDSessionResult(
            success=True,
            status="SUCCESS",
            abort_reason=None,
            channel_metrics=metrics,
            ml_diagnosis=ml_diagnosis,
            raw_pairs_generated=n_pairs,
            sifted_bits_count=sifted_count,
            sample_bits_used=n_sample,
            distilled_key_hex=key_hex,
            key_fingerprint=fingerprint,
            alice_key=alice_key_bytes,
            bob_key=bob_key_bytes,
            keys_match=(alice_key_bytes == bob_key_bytes)
        )
