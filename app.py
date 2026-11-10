"""
Streamlit Web Dashboard for EAQKD System.
Features:
  - Live Quantum Optical Simulation of EAQKD channel under various attacks
  - Real-time XGBoost ML Attack Probability and Threat Categorization
  - Conditional AES-256-GCM Encryption / Decryption Terminal
  - Custom Telemetry Diagnostics
  - Explainable AI (XAI) and Model Performance Visualizer
"""

import os
import json
import numpy as np
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns

from src.pipeline import EAQKDSecureSystem
from src.aes_cipher import AESQuantumCipher
from src.ml_detector import MLAttackDetector

st.set_page_config(
    page_title="EAQKD Quantum Defense & AES System",
    page_icon="⚛️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .metric-card {
        background-color: #1a1e24;
        border-radius: 10px;
        padding: 15px;
        border: 1px solid #2e3846;
        margin-bottom: 10px;
    }
    .status-safe {
        background-color: #0e3a2f;
        color: #25d366;
        padding: 12px;
        border-radius: 8px;
        border: 1px solid #25d366;
        font-weight: bold;
    }
    .status-abort {
        background-color: #3d1419;
        color: #ff4b4b;
        padding: 12px;
        border-radius: 8px;
        border: 1px solid #ff4b4b;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_system():
    return EAQKDSecureSystem(attack_threshold=0.50, max_tolerable_qber=11.0)

system = load_system()

# Sidebar
st.sidebar.title("⚛️ EAQKD Control Hub")
st.sidebar.markdown("**Entanglement-Assisted QKD + XGBoost + AES-256**")

nav_choice = st.sidebar.radio(
    "Navigation",
    [
        "🚀 Live EAQKD Simulation & AES Comms",
        "🧪 Custom Telemetry Diagnostic",
        "📊 ML Model Performance & XAI",
        "📈 Dataset Explorer & Physics Foundations"
    ]
)

st.sidebar.markdown("---")
st.sidebar.subheader("Quantum Channel Config")
distance = st.sidebar.slider("Fiber Distance (km)", min_value=1.0, max_value=140.0, value=25.0, step=1.0)
fiber_loss_rate = st.sidebar.slider("Fiber Loss Rate (dB/km)", min_value=0.15, max_value=0.35, value=0.20, step=0.01)
base_noise = st.sidebar.slider("Detector Dark Counts (cps)", min_value=100.0, max_value=3000.0, value=850.0, step=50.0)

st.sidebar.subheader("Threat Model Injection")
attack_choice = st.sidebar.selectbox(
    "Simulate Eavesdropping Attack",
    ["None (Clean Channel)", "Intercept_Resend", "Detector_Blinding", "Jamming_DoS", "PNS"]
)
attack_intensity = st.sidebar.slider("Attack Intensity", min_value=0.1, max_value=1.0, value=0.85, step=0.05)

st.sidebar.subheader("Security Policies")
qber_thresh = st.sidebar.slider("Max Tolerable QBER (%)", min_value=5.0, max_value=15.0, value=11.0, step=0.5)
ml_prob_thresh = st.sidebar.slider("ML Attack Threshold", min_value=0.2, max_value=0.9, value=0.50, step=0.05)
system.attack_threshold = ml_prob_thresh
system.max_tolerable_qber = qber_thresh

# -----------------------------------------------------------------------------
# PAGE 1: LIVE EAQKD SIMULATION & AES
# -----------------------------------------------------------------------------
if nav_choice == "🚀 Live EAQKD Simulation & AES Comms":
    st.title("🛰️ EAQKD Live Simulation & Quantum-Secured AES Communication")
    st.caption("Entanglement-Assisted Quantum Key Distribution monitored in real-time by XGBoost ML Defense.")

    # Secret Message Box
    st.subheader("1. Message Transmission Payload")
    col_msg1, col_msg2 = st.columns([3, 1])
    with col_msg1:
        user_message = st.text_input(
            "Confidential Message to Transmit via AES-256:",
            value="TOP SECRET: Quantum satellite coordinates 20.45°N, 85.90°E. Encryption active."
        )
    with col_msg2:
        st.markdown("<br>", unsafe_allow_html=True)
        run_sim = st.button("▶️ Execute EAQKD Exchange", use_container_width=True, type="primary")

    attack_key = "None" if "None" in attack_choice else attack_choice
    session = system.run_secure_session(
        message=user_message,
        distance_km=distance,
        attack_type=attack_key,
        attack_intensity=attack_intensity,
        n_qubits=2048
    )

    m = session['channel_telemetry']

    # Security Status Banner
    st.markdown("---")
    st.subheader("2. Quantum Security Operations Center (SOC)")
    
    col_status1, col_status2 = st.columns([2, 1])
    with col_status1:
        if session['key_distribution_success']:
            st.markdown(f"""
            <div class='status-safe'>
                ✅ CHANNEL STATUS: SECURE & VERIFIED<br>
                Decision: {session['ml_security_action']}<br>
                Status: {session['ml_status_message']}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class='status-abort'>
                🚨 CHANNEL STATUS: COMPROMISED / ATTACK DETECTED<br>
                Decision: {session['ml_security_action']}<br>
                Reason: {session['abort_reason']}
            </div>
            """, unsafe_allow_html=True)

    with col_status2:
        prob = session['ml_attack_probability'] * 100.0
        st.metric("XGBoost P(Attack)", f"{prob:.2f}%", delta=f"{session['ml_threat_level']}")
        st.progress(float(session['ml_attack_probability']))

    # Telemetry metrics row
    st.markdown("##### Real-Time Channel Telemetry")
    col_m1, col_m2, col_m3, col_m4, col_m5, col_m6 = st.columns(6)
    col_m1.metric("QBER", f"{m['qber']:.3f}%", delta="Normal < 11%" if m['qber'] < 11.0 else "DANGER", delta_color="inverse")
    col_m2.metric("Photon Loss", f"{m['photon_loss_db']:.2f} dB")
    col_m3.metric("Key Rate", f"{m['key_rate_kbps']:.3f} kbps")
    col_m4.metric("Coincidence Delay", f"{m['delay_ns']:.3f} ns")
    col_m5.metric("Noise Level", f"{m['noise_level_cps']:.1f} cps")
    col_m6.metric("Bell CHSH (S)", f"{m['bell_parameter_s']:.3f}", delta="Quantum > 2.0" if m['bell_parameter_s'] > 2.0 else "Classical <= 2.0")

    # Threat classification breakdown
    col_chart1, col_chart2 = st.columns([1, 1])
    with col_chart1:
        st.markdown("##### XGBoost Attack Class Probabilities")
        probs_df = pd.DataFrame(
            list(session['class_probabilities'].items()),
            columns=['Attack Category', 'Probability']
        )
        fig_prob, ax_prob = plt.subplots(figsize=(6, 3))
        colors = ['#ff4b4b' if c == session['ml_detected_attack_type'] and c != 'Normal' else '#25d366' if c == 'Normal' else '#4b7bec' for c in probs_df['Attack Category']]
        ax_prob.barh(probs_df['Attack Category'], probs_df['Probability'], color=colors)
        ax_prob.set_xlim(0, 1.0)
        ax_prob.set_xlabel("Probability")
        plt.tight_layout()
        st.pyplot(fig_prob)
        plt.close()

    with col_chart2:
        st.markdown("##### XAI Feature Contributions (Anomaly Shifts)")
        feat_df = pd.DataFrame(
            list(session['feature_contributions'].items())[:6],
            columns=['Feature', 'SHAP / Contribution']
        )
        fig_f, ax_f = plt.subplots(figsize=(6, 3))
        ax_f.barh(feat_df['Feature'], feat_df['SHAP / Contribution'], color='#f39c12')
        ax_f.set_xlabel("Impact on Attack Probability")
        plt.tight_layout()
        st.pyplot(fig_f)
        plt.close()

    # 3. Quantum Security Score & Information Leakage Risk
    st.markdown("---")
    st.subheader("3. Holistic Security Score & Information Leakage Analysis")
    sec_info = session.get('security_score', {})
    subscores = sec_info.get('subscores', {})
    leak = sec_info.get('leakage_analysis', {})

    col_sec1, col_sec2, col_sec3, col_sec4, col_sec5 = st.columns(5)
    col_sec1.metric("Security Score", f"{sec_info.get('overall_security_score', 0):.1f}/100", delta=sec_info.get('rating', ''))
    col_sec2.metric("QBER Health", f"{subscores.get('qber_health_score', 0):.1f}/100")
    col_sec3.metric("Bell Entanglement", f"{subscores.get('bell_entanglement_score', 0):.1f}/100")
    col_sec4.metric("ML Integrity", f"{subscores.get('ml_integrity_score', 0):.1f}/100")
    col_sec5.metric("Throughput Health", f"{subscores.get('key_rate_throughput_score', 0):.1f}/100")

    col_leak1, col_leak2 = st.columns([1, 1])
    with col_leak1:
        st.markdown(f"**Leakage Risk Tier:** `{leak.get('leakage_risk_tier', 'N/A')}`")
        st.markdown(f"**Eve's Holevo Mutual Info Bound:** `{leak.get('eve_information_upper_bound_bits', 0):.4f} bits/photon`")
        st.markdown(f"**Secrecy Capacity Fraction:** `{leak.get('secrecy_capacity_fraction', 0)*100:.1f}%`")
    with col_leak2:
        st.info(f"💡 **Mitigation Recommendation:** {leak.get('mitigation_recommendation', 'N/A')}")

    # 4. Adaptive Parameter Optimization
    st.markdown("---")
    st.subheader("4. Adaptive Parameter Optimization (Physics-ML Closed Loop)")
    adapt = session.get('adaptive_optimization', {})
    col_ad1, col_ad2, col_ad3, col_ad4 = st.columns(4)
    col_ad1.metric("Optimal Basis (Z / X)", f"{adapt.get('optimal_p_z_basis', 0.5)*100:.0f}% / {adapt.get('optimal_p_x_basis', 0.5)*100:.0f}%")
    col_ad2.metric("Sifting Efficiency", f"{adapt.get('expected_sifting_efficiency_pct', 50):.1f}%", delta="+24.5% boost" if adapt.get('expected_sifting_efficiency_pct', 50) > 50 else "Standard")
    col_ad3.metric("Coincidence Window", f"{adapt.get('optimal_coincidence_window_ns', 2.5):.1f} ns")
    col_ad4.metric("Anti-Blinding Shutter", "ACTIVE (+15 dB)" if adapt.get('anti_blinding_protection', False) else "Disengaged")

    with st.expander("🛠️ View Dynamic Adaptations Applied in Real-Time"):
        for act in adapt.get('adaptations_applied', []):
            st.write(f"- {act}")

    # Cryptography Execution Section
    st.markdown("---")
    st.subheader("5. AES-256-GCM Authenticated Encryption Pipeline")

    if session['key_distribution_success']:
        st.success("Quantum Key Established Successfully! Authenticated AES-256-GCM Encryption Complete.")
        col_k1, col_k2 = st.columns([2, 1])
        with col_k1:
            st.code(f"EAQKD 256-bit Key: {session['quantum_key_hex']}", language="text")
        with col_k2:
            st.code(f"Key Fingerprint: {session['key_fingerprint']}", language="text")

        aes = session['aes_encryption']
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.markdown("**Alice's Transmitter:**")
            st.write(f"Plaintext: `{aes['plaintext']}`")
            st.write(f"Nonce (96-bit IV): `{aes['nonce_hex']}`")
            st.write(f"Ciphertext + Auth Tag: `{aes['ciphertext_hex']}`")
        with col_c2:
            st.markdown("**Bob's Receiver:**")
            st.write(f"Decrypted Message: `{aes['decrypted_plaintext']}`")
            st.write(f"Authentication Verified: **{aes['authentication_verified']}** (128-bit MAC Match)")

        # Tamper Simulation test
        with st.expander("🛡️ Test Ciphertext Tamper Resilience (Man-in-the-Middle on Classical Channel)"):
            st.write("Simulate an attacker altering the ciphertext in transit over the classical public channel:")
            ct_bytes = bytearray.fromhex(aes['ciphertext_hex'])
            ct_bytes[0] ^= 0xFF  # alter first byte
            tampered_cipher = AESQuantumCipher(session['quantum_key_hex'])
            tampered_res = tampered_cipher.decrypt(ct_bytes.hex(), aes['nonce_hex'])
            st.error(f"Tamper Result: {tampered_res['error']}")
    else:
        st.error("⚠️ SECURE TRANSMISSION HALTED BY QUANTUM INTEGRITY CHECK")
        st.markdown(f"""
        Because an attack was detected (**{session['ml_detected_attack_type']}** with {session['ml_attack_probability']*100:.2f}% probability),
        the key distribution protocol **aborted immediately**.
        
        - Alice's message was **NOT transmitted**.
        - No quantum key was released to the cryptographic layer.
        - Eve obtains zero information about the secret message.
        """)

# -----------------------------------------------------------------------------
# PAGE 2: CUSTOM TELEMETRY DIAGNOSTIC
# -----------------------------------------------------------------------------
elif nav_choice == "🧪 Custom Telemetry Diagnostic":
    st.title("🧪 Custom Quantum Telemetry Diagnostic Tool")
    st.markdown("Manually input optical channel telemetry metrics to query the trained XGBoost model.")

    col1, col2 = st.columns(2)
    with col1:
        c_qber = st.number_input("QBER (%)", min_value=0.0, max_value=50.0, value=22.5, step=0.1)
        c_loss = st.number_input("Photon Loss (dB)", min_value=0.0, max_value=50.0, value=12.0, step=0.1)
        c_noise = st.number_input("Noise Level (cps)", min_value=0.0, max_value=100000.0, value=900.0, step=10.0)
    with col2:
        c_dist = st.number_input("Distance (km)", min_value=0.0, max_value=200.0, value=50.0, step=1.0)
        c_key_rate = st.number_input("Key Rate (kbps)", min_value=0.0, max_value=50.0, value=0.0, step=0.1)
        c_delay = st.number_input("Coincidence Delay (ns)", min_value=0.0, max_value=30.0, value=5.1, step=0.1)

    diag = system.evaluate_custom_telemetry(
        qber=c_qber,
        photon_loss_db=c_loss,
        noise_level_cps=c_noise,
        distance_km=c_dist,
        key_rate_kbps=c_key_rate,
        delay_ns=c_delay
    )

    st.markdown("---")
    st.subheader("Diagnostic Assessment")
    
    col_d1, col_d2, col_d3 = st.columns(3)
    col_d1.metric("Attack Probability", f"{diag['attack_probability']*100:.2f}%")
    col_d2.metric("Predicted Scenario", diag['predicted_attack_type'])
    col_d3.metric("Security Action", diag['security_action'])

    st.info(f"Diagnosis: {diag['status_message']}")

    # Security score display for custom input
    sec = diag.get('security_score', {})
    if sec:
        st.markdown("##### Security Score & Leakage Assessment")
        col_s1, col_s2, col_s3 = st.columns(3)
        col_s1.metric("Security Score", f"{sec.get('overall_security_score', 0):.1f}/100", delta=sec.get('rating', ''))
        leak = sec.get('leakage_analysis', {})
        col_s2.metric("Leakage Risk", leak.get('leakage_risk_tier', 'N/A'))
        col_s3.metric("Eve Holevo Bound", f"{leak.get('eve_information_upper_bound_bits', 0):.4f} bits")

    st.markdown("##### Multi-Class Distribution")
    probs_df = pd.DataFrame(
        list(diag['class_probabilities'].items()),
        columns=['Class', 'Probability']
    )
    st.dataframe(probs_df, use_container_width=True)

# -----------------------------------------------------------------------------
# PAGE 3: ML MODEL PERFORMANCE & XAI
# -----------------------------------------------------------------------------
elif nav_choice == "📊 ML Model Performance & XAI":
    st.title("📊 XGBoost Model Performance & Explainable AI (XAI)")
    st.markdown("Evaluation metrics, ROC curves, confusion matrix, and feature importances for EAQKD attack detection.")

    models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
    report_file = os.path.join(models_dir, 'metrics_report.json')
    
    if os.path.exists(report_file):
        with open(report_file, 'r') as f:
            rep = json.load(f)
            
        b = rep['binary_metrics']
        col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
        col_m1.metric("Accuracy", f"{b['accuracy']*100:.2f}%")
        col_m2.metric("Precision", f"{b['precision']*100:.2f}%")
        col_m3.metric("Recall", f"{b['recall']*100:.2f}%")
        col_m4.metric("F1-Score", f"{b['f1_score']*100:.2f}%")
        col_m5.metric("ROC-AUC", f"{b['roc_auc']:.4f}")

        st.markdown("---")
        st.subheader("Model Benchmarks (Comparative Study)")
        bench_df = pd.DataFrame(rep['benchmarks']).T
        st.dataframe(bench_df.style.highlight_max(axis=0, color='#25d366'), use_container_width=True)

    col_img1, col_img2 = st.columns(2)
    roc_img = os.path.join(models_dir, 'roc_curve.png')
    cm_img = os.path.join(models_dir, 'confusion_matrix.png')
    fi_img = os.path.join(models_dir, 'feature_importance.png')

    with col_img1:
        if os.path.exists(roc_img):
            st.image(roc_img, caption="Receiver Operating Characteristic (ROC) Comparison")
    with col_img2:
        if os.path.exists(cm_img):
            st.image(cm_img, caption="Confusion Matrix - Multi-Class Threat Identification")

    if os.path.exists(fi_img):
        st.markdown("---")
        st.subheader("Feature Importance Analysis (XAI)")
        st.image(fi_img, caption="XGBoost Feature Importance Ranking for EAQKD Attack Detection")

# -----------------------------------------------------------------------------
# PAGE 4: DATASET EXPLORER & PHYSICS FOUNDATIONS
# -----------------------------------------------------------------------------
elif nav_choice == "📈 Dataset Explorer & Physics Foundations":
    st.title("📈 EAQKD Synthetic Dataset Explorer & Physics Foundations")
    
    data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'eaqkd_attack_dataset.csv')
    if os.path.exists(data_path):
        df = pd.read_csv(data_path)
        st.write(f"Total Dataset Records: **{df.shape[0]}** | Features: **{df.shape[1]}**")
        st.dataframe(df.head(100), use_container_width=True)

        st.subheader("Attack Class Distribution")
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.bar_chart(df['attack_type'].value_counts())
        with col_c2:
            st.write("Summary Statistics:")
            st.dataframe(df.describe().T[['mean', 'std', 'min', 'max']], use_container_width=True)

    st.markdown("---")
    st.subheader("Quantum Optical Threat Models Explained")
    st.markdown(r"""
    1. **Intercept-Resend Attack**:
       - Eve measures the transmitted photons in a randomly guessed basis and resends a replacement photon.
       - Physics signature: Causes 25% base mismatch error rate ($QBER > 15\%$), collapses Bell inequality ($S \le 2.0$), and adds electro-optical delay.
    2. **Detector Blinding Attack**:
       - Eve floods APD detectors with continuous-wave (CW) laser light, forcing them from single-photon Geiger mode into classical linear mode.
       - Physics signature: Dark counts drop to near 0, QBER appears unnaturally flat ($< 0.8\%$), and timing jitter collapses.
    3. **Trojan Horse / Jamming Attack (DoS)**:
       - Eve injects high-power probe pulses or floods the quantum channel with excess photons.
       - Physics signature: Noise level skyrockets ($> 15,000 \text{ cps}$), QBER spikes ($> 12\%$), delay jitter expands.
    4. **Photon Number Splitting (PNS) Attack**:
       - Eve taps multi-photon pulses from the source and substitutes standard fiber with a superconducting low-loss link.
       - Physics signature: Measured photon loss is anomalously low for the given fiber distance, while QBER remains modest.
    """)
