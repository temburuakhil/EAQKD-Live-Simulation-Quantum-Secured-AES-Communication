"""
Machine Learning Attack Detector for EAQKD System.
Loads trained XGBoost models to:
  1. Compute probability of attack P(Attack) in [0, 1]
  2. Classify exact attack type (Normal, Intercept_Resend, Detector_Blinding, Jamming_DoS, PNS)
  3. Generate Explainable AI (XAI) feature importance contributions (SHAP / deviation analysis)
  4. Provide automated security decision (PROCEED vs ABORT)
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

class MLAttackDetector:
    """Wrapper for XGBoost models performing real-time security inference."""
    
    def __init__(self, models_dir=None):
        if models_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            models_dir = os.path.join(base_dir, 'models')
            
        self.models_dir = models_dir
        self.bin_model_path = os.path.join(models_dir, 'eaqkd_xgboost_binary.json')
        self.mc_model_path = os.path.join(models_dir, 'eaqkd_xgboost_multiclass.json')
        self.label_enc_path = os.path.join(models_dir, 'label_encoder.joblib')
        self.features_path = os.path.join(models_dir, 'feature_names.json')
        
        self._load_artifacts()
        
    def _load_artifacts(self):
        """Loads models, feature definitions, and label encoders."""
        if not os.path.exists(self.bin_model_path):
            raise FileNotFoundError(f"Model not found at {self.bin_model_path}. Run models/train_xgboost.py first.")
            
        # Load binary classifier
        self.bin_model = xgb.XGBClassifier()
        self.bin_model.load_model(self.bin_model_path)
        
        # Load multi-class classifier
        self.mc_model = xgb.XGBClassifier()
        self.mc_model.load_model(self.mc_model_path)
        
        # Load label encoder & features list
        self.label_enc = joblib.load(self.label_enc_path)
        with open(self.features_path, 'r') as f:
            self.feature_names = json.load(f)
            
        self.class_names = list(self.label_enc.classes_)
        
        # Initialize SHAP explainer if available
        self.explainer = None
        if SHAP_AVAILABLE:
            try:
                self.explainer = shap.TreeExplainer(self.bin_model)
            except Exception:
                self.explainer = None

    def _prepare_feature_row(self, metrics: dict) -> pd.DataFrame:
        """
        Validates and formats the input features.
        Accepts both full feature dict or minimum subset [distance, loss, noise, qber, key_rate, delay].
        """
        row = {}
        for feat in self.feature_names:
            if feat in metrics:
                row[feat] = float(metrics[feat])
            elif feat == 'visibility':
                q = float(metrics.get('qber', 2.0))
                row[feat] = max(0.0, 1.0 - 2.0 * (q / 100.0))
            elif feat == 'bell_parameter_s':
                vis = row.get('visibility', 0.96)
                row[feat] = 2.0 * np.sqrt(2.0) * vis
            elif feat == 'phase_error_rate':
                q = float(metrics.get('qber', 2.0))
                row[feat] = q * 1.02
            else:
                row[feat] = 0.0
                
        return pd.DataFrame([row])[self.feature_names]

    def predict(self, metrics: dict, threshold: float = 0.50) -> dict:
        """
        Infers attack probability, predicted attack type, threat level, and security action.
        
        Args:
            metrics: dict containing quantum channel metrics
            threshold: attack probability threshold to trigger security abort (default 0.50)
            
        Returns:
            dict with complete diagnosis, probabilities, explainability, and action.
        """
        df_row = self._prepare_feature_row(metrics)
        
        # 1. Binary prediction (P(Attack))
        prob_attack = float(self.bin_model.predict_proba(df_row)[0, 1])
        is_attack = bool(prob_attack >= threshold)
        
        # 2. Multi-class prediction (Attack Type)
        mc_probs = self.mc_model.predict_proba(df_row)[0]
        mc_pred_idx = int(np.argmax(mc_probs))
        pred_attack_type = self.class_names[mc_pred_idx]
        
        class_prob_dict = {
            cls: round(float(mc_probs[i]), 4)
            for i, cls in enumerate(self.class_names)
        }
        
        # 3. Determine Threat Level & Security Action
        qber_val = float(metrics.get('qber', 0.0))
        if prob_attack >= 0.70 or qber_val >= 11.0:
            threat_level = "CRITICAL"
            security_action = "ABORT_KEY_EXCHANGE"
            status_message = f"DANGER: Active attack detected ({pred_attack_type})! QKD channel compromised."
        elif prob_attack >= threshold or qber_val >= 8.5:
            threat_level = "ELEVATED"
            security_action = "ABORT_KEY_EXCHANGE"
            status_message = f"WARNING: Anomalous channel behavior detected ({pred_attack_type}). Suspected eavesdropping."
        elif prob_attack >= 0.20:
            threat_level = "LOW_RISK"
            security_action = "PROCEED_WITH_CAUTION"
            status_message = "CAUTION: Channel exhibits minor fluctuations, but within security tolerances."
        else:
            threat_level = "SECURE"
            security_action = "PROCEED_WITH_KEY_DISTILLATION"
            status_message = "SECURE: Quantum channel integrity verified. Zero eavesdropping signatures detected."

        # 4. Explainable AI Feature Contributions
        explanation = {}
        if self.explainer is not None:
            try:
                shap_vals = self.explainer.shap_values(df_row)
                if isinstance(shap_vals, list):
                    shap_vals = shap_vals[1]  # positive class
                if len(shap_vals.shape) > 1:
                    shap_vals = shap_vals[0]
                for f_name, s_val in zip(self.feature_names, shap_vals):
                    explanation[f_name] = round(float(s_val), 4)
            except Exception:
                explanation = self._heuristic_explanation(df_row.iloc[0].to_dict())
        else:
            explanation = self._heuristic_explanation(df_row.iloc[0].to_dict())

        return {
            'attack_probability': round(prob_attack, 4),
            'is_attack': is_attack,
            'threat_level': threat_level,
            'security_action': security_action,
            'status_message': status_message,
            'predicted_attack_type': pred_attack_type,
            'class_probabilities': class_prob_dict,
            'feature_contributions': explanation,
            'telemetry_snapshot': df_row.iloc[0].to_dict()
        }

    def _heuristic_explanation(self, row: dict) -> dict:
        """Fallback explainer indicating deviation from nominal physics baselines."""
        exp = {}
        # Normal baseline reference values
        qber = row.get('qber', 2.0)
        dist = row.get('distance_km', 25.0)
        loss = row.get('photon_loss_db', 6.0)
        noise = row.get('noise_level_cps', 850.0)
        delay = row.get('delay_ns', 2.5)
        
        exp['qber'] = round((qber - 2.5) / 5.0, 3)
        exp['noise_level_cps'] = round((noise - 850.0) / 2000.0, 3)
        expected_loss = 0.20 * dist + 1.8
        exp['photon_loss_db'] = round((loss - expected_loss) / 3.0, 3)
        exp['delay_ns'] = round((delay - (2.1 + 0.018 * dist)) / 1.5, 3)
        return exp
