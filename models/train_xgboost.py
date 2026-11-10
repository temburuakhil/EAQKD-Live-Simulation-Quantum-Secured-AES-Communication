"""
Training Script for EAQKD Attack Detection using XGBoost.
Trains:
  1. XGBoost Binary Classifier: Predicts P(Attack) in [0, 1]
  2. XGBoost Multi-Class Classifier: Identifies specific attack category:
     (Normal, Intercept_Resend, Detector_Blinding, Jamming_DoS, PNS)
  3. Benchmarks against Random Forest & LightGBM for comparative evaluation
  4. Generates evaluation metrics, ROC-AUC curve, Confusion Matrix, and Feature Importance plots.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, confusion_matrix, classification_report
)
from sklearn.ensemble import RandomForestClassifier

import xgboost as xgb
import lightgbm as lgb

def train_and_evaluate():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(base_dir, 'data', 'eaqkd_attack_dataset.csv')
    models_dir = os.path.join(base_dir, 'models')
    os.makedirs(models_dir, exist_ok=True)

    print(f"Loading dataset from: {data_path}")
    df = pd.read_csv(data_path)
    print(f"Dataset shape: {df.shape}")

    feature_cols = [
        'distance_km',
        'photon_loss_db',
        'noise_level_cps',
        'qber',
        'key_rate_kbps',
        'delay_ns',
        'visibility',
        'bell_parameter_s',
        'phase_error_rate'
    ]

    X = df[feature_cols].copy()
    y_binary = df['attack_detected'].values
    y_type_raw = df['attack_type'].values

    label_enc = LabelEncoder()
    y_multiclass = label_enc.fit_transform(y_type_raw)
    class_names = list(label_enc.classes_)
    print(f"Target classes ({len(class_names)}): {class_names}")

    # Train / Test split (80/20 stratified by attack_type)
    X_train, X_test, y_train_bin, y_test_bin, y_train_mc, y_test_mc = train_test_split(
        X, y_binary, y_multiclass,
        test_size=0.20,
        random_state=42,
        stratify=y_multiclass
    )

    print(f"Train samples: {X_train.shape[0]} | Test samples: {X_test.shape[0]}")

    # Feature Scaling (Fit on Train, transform on Test)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save scaler, label encoder, and feature names
    joblib.dump(scaler, os.path.join(models_dir, 'scaler.joblib'))
    joblib.dump(label_enc, os.path.join(models_dir, 'label_encoder.joblib'))
    with open(os.path.join(models_dir, 'feature_names.json'), 'w') as f:
        json.dump(feature_cols, f, indent=2)

    # =========================================================================
    # 1. XGBOOST BINARY CLASSIFIER (Attack Probability)
    # =========================================================================
    print("\n" + "="*50)
    print("Training XGBoost Binary Classifier (P(Attack))...")
    print("="*50)

    xgb_bin = xgb.XGBClassifier(
        n_estimators=250,
        max_depth=5,
        learning_rate=0.05,
        subsample=0.85,
        colsample_bytree=0.85,
        eval_metric='logloss',
        random_state=42,
        use_label_encoder=False
    )
    xgb_bin.fit(X_train, y_train_bin)

    y_pred_bin = xgb_bin.predict(X_test)
    y_prob_bin = xgb_bin.predict_proba(X_test)[:, 1]

    bin_acc = accuracy_score(y_test_bin, y_pred_bin)
    bin_prec = precision_score(y_test_bin, y_pred_bin)
    bin_rec = recall_score(y_test_bin, y_pred_bin)
    bin_f1 = f1_score(y_test_bin, y_pred_bin)
    bin_auc = roc_auc_score(y_test_bin, y_prob_bin)

    print(f"XGBoost Binary Accuracy:  {bin_acc:.4f}")
    print(f"XGBoost Binary Precision: {bin_prec:.4f}")
    print(f"XGBoost Binary Recall:    {bin_rec:.4f}")
    print(f"XGBoost Binary F1-Score:  {bin_f1:.4f}")
    print(f"XGBoost Binary ROC-AUC:   {bin_auc:.4f}")

    # Save XGBoost binary model
    xgb_bin.save_model(os.path.join(models_dir, 'eaqkd_xgboost_binary.json'))

    # =========================================================================
    # 2. XGBOOST MULTI-CLASS CLASSIFIER (Attack Categorization)
    # =========================================================================
    print("\n" + "="*50)
    print("Training XGBoost Multi-Class Classifier (Attack Types)...")
    print("="*50)

    xgb_mc = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.85,
        colsample_bytree=0.85,
        objective='multi:softprob',
        num_class=len(class_names),
        eval_metric='mlogloss',
        random_state=42
    )
    xgb_mc.fit(X_train, y_train_mc)

    y_pred_mc = xgb_mc.predict(X_test)
    y_prob_mc = xgb_mc.predict_proba(X_test)

    mc_acc = accuracy_score(y_test_mc, y_pred_mc)
    mc_f1 = f1_score(y_test_mc, y_pred_mc, average='macro')
    mc_auc = roc_auc_score(y_test_mc, y_prob_mc, multi_class='ovr', average='macro')

    print(f"XGBoost Multi-Class Accuracy: {mc_acc:.4f}")
    print(f"XGBoost Multi-Class F1-Macro: {mc_f1:.4f}")
    print(f"XGBoost Multi-Class ROC-AUC:  {mc_auc:.4f}")
    print("\nClassification Report (XGBoost Multi-class):")
    print(classification_report(y_test_mc, y_pred_mc, target_names=class_names))

    # Save XGBoost multiclass model
    xgb_mc.save_model(os.path.join(models_dir, 'eaqkd_xgboost_multiclass.json'))

    # =========================================================================
    # 3. BENCHMARK COMPARISON (Random Forest & LightGBM)
    # =========================================================================
    print("\n" + "="*50)
    print("Benchmarking Models for Research Comparison...")
    print("="*50)

    # Random Forest
    rf_model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
    rf_model.fit(X_train, y_train_bin)
    rf_pred = rf_model.predict(X_test)
    rf_prob = rf_model.predict_proba(X_test)[:, 1]
    rf_acc = accuracy_score(y_test_bin, rf_pred)
    rf_auc = roc_auc_score(y_test_bin, rf_prob)
    rf_f1 = f1_score(y_test_bin, rf_pred)

    # LightGBM
    lgb_model = lgb.LGBMClassifier(n_estimators=200, max_depth=6, learning_rate=0.05, random_state=42, verbose=-1)
    lgb_model.fit(X_train, y_train_bin)
    lgb_pred = lgb_model.predict(X_test)
    lgb_prob = lgb_model.predict_proba(X_test)[:, 1]
    lgb_acc = accuracy_score(y_test_bin, lgb_pred)
    lgb_auc = roc_auc_score(y_test_bin, lgb_prob)
    lgb_f1 = f1_score(y_test_bin, lgb_pred)

    benchmark_results = {
        'XGBoost': {
            'Accuracy': round(bin_acc, 5),
            'Precision': round(bin_prec, 5),
            'Recall': round(bin_rec, 5),
            'F1_Score': round(bin_f1, 5),
            'ROC_AUC': round(bin_auc, 5)
        },
        'LightGBM': {
            'Accuracy': round(lgb_acc, 5),
            'Precision': round(precision_score(y_test_bin, lgb_pred), 5),
            'Recall': round(recall_score(y_test_bin, lgb_pred), 5),
            'F1_Score': round(lgb_f1, 5),
            'ROC_AUC': round(lgb_auc, 5)
        },
        'Random_Forest': {
            'Accuracy': round(rf_acc, 5),
            'Precision': round(precision_score(y_test_bin, rf_pred), 5),
            'Recall': round(recall_score(y_test_bin, rf_pred), 5),
            'F1_Score': round(rf_f1, 5),
            'ROC_AUC': round(rf_auc, 5)
        }
    }

    print("\nBenchmark Comparison Summary:")
    print(pd.DataFrame(benchmark_results).T)

    # =========================================================================
    # 4. PLOTS & ARTIFACT GENERATION
    # =========================================================================
    # ROC Curves comparison
    plt.figure(figsize=(8, 6))
    fpr_xgb, tpr_xgb, _ = roc_curve(y_test_bin, y_prob_bin)
    fpr_lgb, tpr_lgb, _ = roc_curve(y_test_bin, lgb_prob)
    fpr_rf, tpr_rf, _ = roc_curve(y_test_bin, rf_prob)

    plt.plot(fpr_xgb, tpr_xgb, label=f'XGBoost (AUC = {bin_auc:.4f})', linewidth=2.5, color='#1f77b4')
    plt.plot(fpr_lgb, tpr_lgb, label=f'LightGBM (AUC = {lgb_auc:.4f})', linewidth=2.0, color='#2ca02c', linestyle='--')
    plt.plot(fpr_rf, tpr_rf, label=f'Random Forest (AUC = {rf_auc:.4f})', linewidth=2.0, color='#ff7f0e', linestyle=':')
    plt.plot([0, 1], [0, 1], 'k--', alpha=0.5)
    plt.xlabel('False Positive Rate (FPR)', fontsize=12)
    plt.ylabel('True Positive Rate (TPR)', fontsize=12)
    plt.title('Receiver Operating Characteristic (ROC) Curve - EAQKD Attack Detection', fontsize=13)
    plt.legend(loc='lower right', fontsize=11)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(models_dir, 'roc_curve.png'), dpi=300)
    plt.close()

    # Confusion Matrix (Multi-Class)
    cm = confusion_matrix(y_test_mc, y_pred_mc)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=class_names, yticklabels=class_names)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('True Label', fontsize=12)
    plt.title('Confusion Matrix - EAQKD Multi-Class Attack Detection (XGBoost)', fontsize=13)
    plt.tight_layout()
    plt.savefig(os.path.join(models_dir, 'confusion_matrix.png'), dpi=300)
    plt.close()

    # Feature Importance Plot
    feat_importances = pd.Series(xgb_bin.feature_importances_, index=feature_cols).sort_values(ascending=True)
    plt.figure(figsize=(9, 6))
    feat_importances.plot(kind='barh', color='#00a884', edgecolor='black')
    plt.xlabel('XGBoost Relative Feature Importance', fontsize=12)
    plt.title('Feature Importance for EAQKD Attack Detection', fontsize=13)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(models_dir, 'feature_importance.png'), dpi=300)
    plt.close()

    # Save comprehensive metrics report
    report_dict = {
        'binary_metrics': {
            'accuracy': bin_acc,
            'precision': bin_prec,
            'recall': bin_rec,
            'f1_score': bin_f1,
            'roc_auc': bin_auc
        },
        'multiclass_metrics': {
            'accuracy': mc_acc,
            'f1_macro': mc_f1,
            'roc_auc_ovr': mc_auc,
            'class_names': class_names
        },
        'benchmarks': benchmark_results,
        'feature_importances': feat_importances.to_dict()
    }
    with open(os.path.join(models_dir, 'metrics_report.json'), 'w') as f:
        json.dump(report_dict, f, indent=2)

    print(f"\nAll models, metrics, and plots saved successfully in: {models_dir}")
    return report_dict

if __name__ == '__main__':
    train_and_evaluate()
