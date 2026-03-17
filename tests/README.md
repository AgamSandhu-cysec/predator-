# 🧪 Predator Enumeration Module Tests

This test suite validates the logic, parsing extraction, and ML structuring of the enumeration module.

## 📦 Setup Instructions

It covers mocked integration and robust parsing.

```bash
# Set up environment
python3 -m venv venv
source venv/bin/activate

# Install test dependencies
pip install -r tests/requirements-test.txt

# Run all automated mock and unit tests (ensure you are running from the predator directory so enumerator module resolves properly)
PYTHONPATH=. pytest tests/
```

## 🎯 Test breakdown
* `test_parsers.py`: Asserts standard logic and extreme edge cases mapped properly to parsed structures.
* `test_feature_extractor.py`: Ensures variables correctly evaluate mapping rules when assigning feature arrays.
* `test_enumerator.py`: Emulates raw OS returns against the enumeration loop.
* `test_against_vm.py`: Needs config, meant to SSH into real servers.
