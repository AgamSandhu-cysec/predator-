# Predator ML Exploit Recommendation Engine

## Overview
Predator uses an advanced Natural Language Processing (NLP) model to map enumeration findings back to available exploit modules. Unlike traditional rule-based fallbacks, this model is robust to variations in output and can generalize findings across various environments.

## Architecture
The ML engine consists of two core components:
1. `train_model.py`: Parses the raw dataset (`linux_window_priv_escalation_datatset.jsonl`), extracts standard command+description texts, and trains a `RandomForestClassifier` initialized within a `TfidfVectorizer` pipeline. It outputs highly-performant `.joblib` model binaries into `ml/models/`.
2. `predictor.py`: The live prediction interface used by the Predator TUI. It loads the `joblib` models dynamically on connection and intercepts successful enumeration outputs.

## Usage
### Retraining the Model
If the underlying dataset is updated with new commands or categories, you can easily retrain the models:

```bash
cd /path/to/predator
python3 ml/train_model.py
```
This script will parse the `.jsonl` files from `tmp_dataset/`, retrain the Scikit-Learn pipelines, display a `classification_report`, and save the updated `.joblib` files to `ml/models/`.

### Category Mapping
The NLP component outputs broad MITRE-style categories (e.g. `SUID Binaries`, `Service Misconfiguration`). `predictor.py` maintains an internal `category_module_map` to link these generic NLP categories directly to our local, executable exploit codes residing in the `exploits/` directory, ensuring smooth 1-click execution from the UI!
