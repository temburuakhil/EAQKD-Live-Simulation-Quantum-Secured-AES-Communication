# Hybrid Physics–ML Based EAQKD System with Explainable Attack Detection and AES-256 Encryption

An end-to-end implementation of an **Entanglement-Assisted Quantum Key Distribution (EAQKD)** system that distributes 256-bit symmetric keys, integrates an **XGBoost Machine Learning model** for real-time attack detection from quantum channel telemetry, and executes **AES-256-GCM** authenticated message encryption.

---

## 📌 Project Overview

Traditional Quantum Key Distribution (QKD) systems rely on rigid, fixed-threshold rules (e.g. aborting solely if $QBER > 11.0\%$). However, sophisticated eavesdropping strategies—such as **Detector Blinding** (which artificially suppresses QBER) or **Photon Number Splitting (PNS)** (which taps multi-photon pulses while maintaining acceptable QBER)—bypass naive single-parameter checks.

This project implements a **Hybrid Physics–Machine Learning defense framework**:
1. **EAQKD Protocol Engine**: Simulates the generation of entangled Bell pairs ($|\Phi^+\rangle$), random basis measurements (Rectilinear $Z$ and Diagonal $X$), sifting, error correction, and privacy amplification.
2. **Physics-Grounded Quantum Optical Channel**: Accurately models single-mode fiber attenuation ($\alpha = 0.20\text{ dB/km}$ at $1550\text{ nm}$), detector quantum efficiency, dark count rate, coincidence delay/jitter, and Bell inequality violation (CHSH parameter $S$).
3. **Machine Learning Security Guard (XGBoost)**: Continuously evaluates multidimensional channel telemetry (`QBER`, `Photon Loss`, `Noise Level`, `Distance`, `Key Rate`, `Delay`, `Visibility`, `Bell S`) to output:
   - **$P(\text{Attack}) \in [0, 1]$**: Continuous probability of an active attack.
   - **Attack Classification**: Normal, Intercept-Resend, Detector Blinding, Jamming/DoS, or PNS.
   - **Automated Policy Decision**: `PROCEED_WITH_KEY_DISTILLATION` vs `ABORT_KEY_EXCHANGE`.
4. **AES-256-GCM Quantum-Secured Cryptography**: Uses the distilled 256-bit symmetric quantum key to encrypt confidential payloads with Galois/Counter Mode (GCM) authenticated encryption and 128-bit MAC tag verification.

---

## 🏗️ System Architecture

```
[ Entangled Photon Source (|Phi+>) ]
            |              |
      (Alice's Arm)  (Bob's Arm)
            |              |
      [ Quantum Fiber Channel (Distance d, Loss alpha, Noise N, Delay tau) ]
                           |
               <--- Eavesdropper Eve Attack --->
          (Intercept-Resend | Blinding | Jamming | PNS)
                           |
      [ Basis Sifting & Channel Parameter Extraction ]
                           |
   +-----------------------v------------------------+
   |  Extracted Physical Channel Telemetry:        |
   |  - QBER (%)            - Key Rate (kbps)      |
   |  - Photon Loss (dB)    - Coincidence Delay    |
   |  - Noise Level (cps)   - Bell Parameter (S)   |
   +-----------------------+------------------------+
                           |
                           v
   +------------------------------------------------+
   |     XGBoost ML Attack Detection Engine         |
   |     Outputs: P(Attack) & Attack Category       |
   +-----------------------+------------------------+
                           |
              Is Channel Compromised?
             /                        \
      [ YES (P > 0.50) ]        [ NO (Clean) ]
            |                          |
     [ ABORT SESSION ]      [ Distill 256-bit Key ]
  (Zero Secret Leakage)                |
                            [ AES-256-GCM Cipher ]
                         (Authenticated Encryption)
```

---

## 📊 Dataset Features & Physical Telemetry

The dataset generator (`data/generate_synthetic_data.py`) produces 15,000 physics-grounded samples across clean and attacked channels:

| Feature Name | Unit | Physical Description |
| :--- | :--- | :--- |
| `distance_km` | km | Transmission fiber distance between Alice and Bob ($1 - 150\text{ km}$) |
| `photon_loss_db` | dB | Total channel attenuation: $\alpha \cdot d + L_{\text{coupling}}$ |
| `noise_level_cps` | cps | APD detector dark counts + stray ambient photon counts |
| `qber` | % | Quantum Bit Error Rate from optical misalignment & noise |
| `key_rate_kbps` | kbps | Sifted and distilled secret key generation rate |
| `delay_ns` | ns | Optical fiber propagation delay and coincidence timing jitter |
| `visibility` | $[0, 1]$ | Bell state quantum interference visibility ($V = 1 - 2\cdot QBER$) |
| `bell_parameter_s` | $[0, 2.83]$ | CHSH inequality Bell parameter ($S = 2\sqrt{2}\cdot V$) |
| `phase_error_rate` | % | Phase error rate $e_x$ measured across complementary bases |

### Target Labels
- `attack_detected`: Binary label (`0` = Normal, `1` = Attack)
- `attack_type`: Categorical label (`Normal`, `Intercept_Resend`, `Detector_Blinding`, `Jamming_DoS`, `PNS`)

---

## 🔬 Modeled Quantum Optical Attacks

1. **Intercept-Resend Attack**:
   - Eve intercepts photons and measures them in random bases ($Z$ or $X$), resending replacement photons.
   - **Telemetry Signature**: Induces $25\%$ bit error rate ($QBER \approx 15\% - 33\%$), collapses Bell inequality ($S \le 2.0$, classical limit), adds electro-optical transceiver delay ($+1.8 - 4.2\text{ ns}$), key rate collapses to $0$.
2. **Detector Blinding Attack**:
   - Eve shines high-intensity continuous-wave (CW) laser light onto Bob's Single-Photon Avalanche Diodes (SPADs), forcing them into classical threshold conduction mode.
   - **Telemetry Signature**: Dark counts plunge to near zero ($< 60\text{ cps}$), QBER appears artificially tiny ($0.08\% - 0.65\%$), timing jitter collapses ($< 1.2\text{ ns}$). Fixed-threshold systems fail here, but XGBoost detects the anomaly immediately.
3. **Trojan Horse / Channel Jamming Attack (DoS)**:
   - Eve injects high-power optical probe pulses or floods the channel with excess photons.
   - **Telemetry Signature**: Noise level explodes ($15,000 - 85,000\text{ cps}$), QBER surges ($14\% - 35\%$), timing jitter broadens ($7 - 16\text{ ns}$), key rate drops to $0$.
4. **Photon Number Splitting (PNS) Attack**:
   - Eve exploits multi-photon emissions by tapping one photon and substituting the lossy fiber with an engineered lower-loss channel.
   - **Telemetry Signature**: Measured photon loss is anomalously low for the given fiber distance ($4 - 11\text{ dB}$ lower than expected), while QBER stays deceptively low ($3.5\% - 7.5\%$).

---

## 📈 Machine Learning Performance & Benchmarks

The XGBoost models were trained on an 80/20 train/test split (12,000 training samples, 3,000 test samples):

### Binary Classification Performance ($P(\text{Attack})$)
- **Accuracy**: `99.97%`
- **Precision**: `100.00%`
- **Recall**: `99.93%`
- **F1-Score**: `0.9997`
- **ROC-AUC**: `1.0000`

### Multi-Class Classification Performance (Attack Categorization)
- **Accuracy**: `100.00%`
- **Macro F1**: `1.0000`
- **ROC-AUC (OVR)**: `1.0000`

### Benchmark Comparison

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **XGBoost** | **0.99967** | **1.0000** | **0.99933** | **0.99967** | **1.0000** |
| LightGBM | 1.00000 | 1.0000 | 1.00000 | 1.00000 | 1.0000 |
| Random Forest | 1.00000 | 1.0000 | 1.00000 | 1.00000 | 1.0000 |

Artifact plots generated and saved in `models/`:
- `roc_curve.png`: ROC comparison curves.
- `confusion_matrix.png`: Multi-class confusion matrix heatmap.
- `feature_importance.png`: Relative feature importance ranking.

---

## 📁 Repository Structure

```
d:\Bibek Project\
├── data/
│   ├── generate_synthetic_data.py       # Physics simulation dataset generator
│   └── eaqkd_attack_dataset.csv         # 15,000 sample synthetic QKD dataset
├── models/
│   ├── train_xgboost.py                 # Training & evaluation pipeline
│   ├── eaqkd_xgboost_binary.json        # Saved XGBoost binary model
│   ├── eaqkd_xgboost_multiclass.json    # Saved XGBoost multi-class model
│   ├── scaler.joblib                    # Feature standardizer
│   ├── label_encoder.joblib             # Class label encoder
│   ├── feature_names.json               # Input feature schema
│   ├── metrics_report.json              # Full metrics and benchmark json
│   ├── roc_curve.png                    # ROC curve visualization
│   ├── confusion_matrix.png             # Multi-class confusion matrix plot
│   └── feature_importance.png           # Feature importance bar plot
├── src/
│   ├── __init__.py                      # Package entry point
│   ├── physics_channel.py               # Bell state generation & optical fiber physics
│   ├── attacks.py                       # Intercept-Resend, Blinding, Jamming, PNS attacks
│   ├── ml_detector.py                   # XGBoost inference wrapper & XAI explainer
│   ├── eaqkd_protocol.py                # EAQKD exchange, sifting & key distillation
│   ├── aes_cipher.py                    # AES-256-GCM encryption/decryption module
│   └── pipeline.py                      # End-to-end integration orchestrator
├── app.py                               # Interactive Streamlit Web Application
├── main.py                              # End-to-end CLI demonstration script
├── test_system.py                       # 9 unit & integration tests
├── requirements.txt                     # Python dependencies
└── README.md                            # Comprehensive project documentation
```

---

## 🚀 How to Run the Project

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. (Optional) Re-generate Synthetic Dataset
```bash
python data/generate_synthetic_data.py
```

### 3. (Optional) Re-train & Benchmark XGBoost Models
```bash
python models/train_xgboost.py
```

### 4. Run CLI Demonstration
Demonstrates clean key exchange + AES-256 encryption vs all four attack scenarios:
```bash
python main.py
```

### 5. Launch the Interactive Web Dashboard
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501` to:
- Adjust fiber distance, attenuation, and noise in real-time.
- Inject simulated quantum attacks (Intercept-Resend, Blinding, Jamming, PNS).
- Watch the XGBoost security guard calculate $P(\text{Attack})$ and classify the threat.
- Transmit confidential messages through AES-256-GCM and verify integrity tags.
- Query custom telemetry numbers and inspect Explainable AI (XAI) feature contributions.

### 6. Run Test Suite
```bash
python -m pytest -v test_system.py
```
All 9 unit tests verify channel physics, threat models, XGBoost inference, AES encryption, and tamper resilience.
