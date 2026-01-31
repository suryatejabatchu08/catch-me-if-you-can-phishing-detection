"""
ML Model Training and Prediction
Trains and uses Random Forest and Logistic Regression models
"""
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from typing import Dict, Any, Tuple, Optional
import logging
import time

from config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class PhishingMLModel:
    """ML Model for phishing detection"""
    
    def __init__(self):
        self.model_primary = None
        self.model_fallback = None
        self.feature_names = []
        self.model_version = settings.MODEL_VERSION
        self.models_dir = settings.ML_MODEL_PATH
        
        # Ensure models directory exists
        os.makedirs(self.models_dir, exist_ok=True)
    
    def train(self, df: pd.DataFrame, target_column: str = 'label') -> Dict[str, Any]:
        """
        Train both primary and fallback models
        
        Args:
            df: DataFrame with features and target
            target_column: Name of target column (0=safe, 1=phishing)
        
        Returns:
            Training metrics and performance
        """
        logger.info("Starting model training...")
        start_time = time.time()
        
        # Prepare data
        X = df.drop(columns=[target_column])
        y = df[target_column]
        
        # Store feature names
        self.feature_names = list(X.columns)
        
        # Train-test split (80-20)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        results = {}
        
        # Train primary model (Random Forest)
        logger.info("Training Random Forest (primary)...")
        self.model_primary = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.model_primary.fit(X_train, y_train)
        
        # Evaluate primary model
        y_pred_primary = self.model_primary.predict(X_test)
        y_prob_primary = self.model_primary.predict_proba(X_test)[:, 1]
        
        results['primary'] = {
            'model': 'RandomForest',
            'accuracy': float(self.model_primary.score(X_test, y_test)),
            'auc_roc': float(roc_auc_score(y_test, y_prob_primary)),
            'classification_report': classification_report(y_test, y_pred_primary, output_dict=True),
            'confusion_matrix': confusion_matrix(y_test, y_pred_primary).tolist(),
            'feature_importance': dict(zip(
                self.feature_names,
                self.model_primary.feature_importances_.tolist()
            ))
        }
        
        # Train fallback model (Logistic Regression)
        logger.info("Training Logistic Regression (fallback)...")
        self.model_fallback = LogisticRegression(
            max_iter=1000,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        self.model_fallback.fit(X_train, y_train)
        
        # Evaluate fallback model
        y_pred_fallback = self.model_fallback.predict(X_test)
        y_prob_fallback = self.model_fallback.predict_proba(X_test)[:, 1]
        
        results['fallback'] = {
            'model': 'LogisticRegression',
            'accuracy': float(self.model_fallback.score(X_test, y_test)),
            'auc_roc': float(roc_auc_score(y_test, y_prob_fallback)),
            'classification_report': classification_report(y_test, y_pred_fallback, output_dict=True),
            'confusion_matrix': confusion_matrix(y_test, y_pred_fallback).tolist()
        }
        
        # Cross-validation
        logger.info("Running cross-validation...")
        cv_scores_primary = cross_val_score(self.model_primary, X, y, cv=5)
        cv_scores_fallback = cross_val_score(self.model_fallback, X, y, cv=5)
        
        results['cross_validation'] = {
            'primary_scores': cv_scores_primary.tolist(),
            'primary_mean': float(cv_scores_primary.mean()),
            'fallback_scores': cv_scores_fallback.tolist(),
            'fallback_mean': float(cv_scores_fallback.mean())
        }
        
        training_time = time.time() - start_time
        results['training_time_seconds'] = round(training_time, 2)
        results['dataset_size'] = len(df)
        results['feature_count'] = len(self.feature_names)
        
        logger.info(f"Training completed in {training_time:.2f}s")
        logger.info(f"Primary model accuracy: {results['primary']['accuracy']:.4f}")
        logger.info(f"Primary model AUC-ROC: {results['primary']['auc_roc']:.4f}")
        
        return results
    
    def predict(self, features: Dict[str, Any], use_fallback: bool = False) -> Dict[str, Any]:
        """
        Predict phishing probability
        
        Args:
            features: Dictionary of feature values
            use_fallback: Use fallback model instead of primary
        
        Returns:
            {
                'ml_prediction': float (0-1),
                'confidence': float,
                'model_used': str,
                'feature_importance': List[Tuple[str, float]],
                'inference_time_ms': float
            }
        """
        start_time = time.time()
        
        try:
            # Select model
            model = self.model_fallback if use_fallback else self.model_primary
            model_name = 'fallback' if use_fallback else 'primary'
            
            if model is None:
                raise ValueError(f"Model {model_name} not loaded")
            
            # Prepare features
            feature_vector = self._prepare_features(features)
            
            # Predict
            prediction = model.predict_proba([feature_vector])[0]
            phishing_prob = float(prediction[1])  # Probability of class 1 (phishing)
            
            # Calculate confidence (distance from 0.5)
            confidence = abs(phishing_prob - 0.5) * 2
            
            # Get feature importance (only for primary model)
            feature_importance = []
            if not use_fallback and hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
                feature_importance = sorted(
                    zip(self.feature_names, importances),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]  # Top 10
            
            inference_time = (time.time() - start_time) * 1000  # Convert to ms
            
            return {
                'ml_prediction': round(phishing_prob, 4),
                'confidence': round(confidence, 4),
                'model_used': model_name,
                'feature_importance': [(name, round(float(imp), 4)) for name, imp in feature_importance],
                'inference_time_ms': round(inference_time, 2)
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            # Fallback to fallback model if primary fails
            if not use_fallback and self.model_fallback:
                logger.info("Falling back to fallback model...")
                return self.predict(features, use_fallback=True)
            raise
    
    def _prepare_features(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert feature dict to numpy array matching training features"""
        # Extract features in correct order
        feature_vector = []
        for feature_name in self.feature_names:
            value = features.get(feature_name, 0)
            # Handle potential type issues
            if isinstance(value, (int, float)):
                feature_vector.append(value)
            else:
                feature_vector.append(0)
        
        return np.array(feature_vector)
    
    def save_models(self):
        """Save trained models to disk"""
        if self.model_primary:
            primary_path = os.path.join(self.models_dir, f'random_forest_{self.model_version}.joblib')
            joblib.dump(self.model_primary, primary_path)
            logger.info(f"Primary model saved to {primary_path}")
        
        if self.model_fallback:
            fallback_path = os.path.join(self.models_dir, f'logistic_regression_{self.model_version}.joblib')
            joblib.dump(self.model_fallback, fallback_path)
            logger.info(f"Fallback model saved to {fallback_path}")
        
        # Save feature names
        features_path = os.path.join(self.models_dir, f'feature_names_{self.model_version}.joblib')
        joblib.dump(self.feature_names, features_path)
        logger.info(f"Feature names saved to {features_path}")
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            primary_path = os.path.join(self.models_dir, f'random_forest_{self.model_version}.joblib')
            fallback_path = os.path.join(self.models_dir, f'logistic_regression_{self.model_version}.joblib')
            features_path = os.path.join(self.models_dir, f'feature_names_{self.model_version}.joblib')
            
            if os.path.exists(primary_path):
                self.model_primary = joblib.load(primary_path)
                logger.info(f"Primary model loaded from {primary_path}")
            
            if os.path.exists(fallback_path):
                self.model_fallback = joblib.load(fallback_path)
                logger.info(f"Fallback model loaded from {fallback_path}")
            
            if os.path.exists(features_path):
                self.feature_names = joblib.load(features_path)
                logger.info(f"Feature names loaded: {len(self.feature_names)} features")
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            return False
    
    def create_sample_dataset(self, num_samples: int = 1000) -> pd.DataFrame:
        """
        Create a sample dataset for demonstration purposes
        This should be replaced with real phishing dataset
        """
        np.random.seed(42)
        
        # Simulated features
        data = {
            'url_length': np.random.randint(10, 200, num_samples),
            'domain_length': np.random.randint(5, 50, num_samples),
            'path_depth': np.random.randint(0, 10, num_samples),
            'subdomain_count': np.random.randint(0, 5, num_samples),
            'digit_ratio': np.random.uniform(0, 0.4, num_samples),
            'special_char_ratio': np.random.uniform(0, 0.5, num_samples),
            'url_entropy': np.random.uniform(2, 5, num_samples),
            'has_ip_address': np.random.choice([0, 1], num_samples, p=[0.9, 0.1]),
            'is_https': np.random.choice([0, 1], num_samples, p=[0.3, 0.7]),
            'suspicious_keyword_count': np.random.randint(0, 5, num_samples),
        }
        
        df = pd.DataFrame(data)
        
        # Create label (simplified logic for demo)
        df['label'] = (
            (df['url_length'] > 75).astype(int) * 0.3 +
            (df['has_ip_address'] == 1).astype(int) * 0.4 +
            (df['suspicious_keyword_count'] >= 2).astype(int) * 0.3 +
            np.random.uniform(0, 0.2, num_samples)
        )
        df['label'] = (df['label'] > 0.5).astype(int)
        
        return df


# Global instance
ml_model = PhishingMLModel()
