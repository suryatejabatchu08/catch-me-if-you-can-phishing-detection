"""
Training script for ML models
Run this to train and save models
"""
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.model import ml_model
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """Train and save ML models"""
    logger.info("=" * 60)
    logger.info("PhishGuard AI - Model Training")
    logger.info("=" * 60)
    
    # Create sample dataset
    # TODO: Replace with real phishing dataset (UCI ML Repository, Kaggle, etc.)
    logger.info("\nGenerating sample dataset...")
    df = ml_model.create_sample_dataset(num_samples=10000)
    logger.info(f"Dataset created: {len(df)} samples")
    logger.info(f"Features: {list(df.columns[:-1])}")
    logger.info(f"Phishing ratio: {df['label'].mean():.2%}")
    
    # Train models
    logger.info("\nTraining models...")
    results = ml_model.train(df, target_column='label')
    
    # Print results
    logger.info("\n" + "=" * 60)
    logger.info("TRAINING RESULTS")
    logger.info("=" * 60)
    
    logger.info("\n📊 PRIMARY MODEL (Random Forest):")
    logger.info(f"  Accuracy: {results['primary']['accuracy']:.4f}")
    logger.info(f"  AUC-ROC: {results['primary']['auc_roc']:.4f}")
    logger.info(f"  Precision: {results['primary']['classification_report']['1']['precision']:.4f}")
    logger.info(f"  Recall: {results['primary']['classification_report']['1']['recall']:.4f}")
    logger.info(f"  F1-Score: {results['primary']['classification_report']['1']['f1-score']:.4f}")
    
    logger.info("\n📊 FALLBACK MODEL (Logistic Regression):")
    logger.info(f"  Accuracy: {results['fallback']['accuracy']:.4f}")
    logger.info(f"  AUC-ROC: {results['fallback']['auc_roc']:.4f}")
    logger.info(f"  Precision: {results['fallback']['classification_report']['1']['precision']:.4f}")
    logger.info(f"  Recall: {results['fallback']['classification_report']['1']['recall']:.4f}")
    logger.info(f"  F1-Score: {results['fallback']['classification_report']['1']['f1-score']:.4f}")
    
    logger.info("\n🔄 Cross-Validation:")
    logger.info(f"  Primary Mean CV Score: {results['cross_validation']['primary_mean']:.4f}")
    logger.info(f"  Fallback Mean CV Score: {results['cross_validation']['fallback_mean']:.4f}")
    
    logger.info(f"\n⏱️  Training Time: {results['training_time_seconds']:.2f} seconds")
    
    # Top feature importance
    logger.info("\n🔝 Top 10 Feature Importance (Primary Model):")
    feature_importance = sorted(
        results['primary']['feature_importance'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    for i, (feature, importance) in enumerate(feature_importance, 1):
        logger.info(f"  {i}. {feature}: {importance:.4f}")
    
    # Save models
    logger.info("\n💾 Saving models...")
    ml_model.save_models()
    
    logger.info("\n✅ Training complete!")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
