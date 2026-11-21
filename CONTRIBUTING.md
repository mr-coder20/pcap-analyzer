# Contributing to PCAP Analyzer

1. Fork → branch → `pip install -r requirements-dev.txt` → `pytest -q`.
2. Keep the app 100 % offline by default (network only on explicit user action, e.g. update check).
3. Never commit real malware or private captures — use `tests/make_test_pcap.py`.
4. Change name/author/version only in `app_meta.py`.

Maintainer: [mr-coder20](https://github.com/mr-coder20) · Issues: https://github.com/mr-coder20/pcap-analyzer/issues
