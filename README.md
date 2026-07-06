# PQC Authentication (Post-Quantum Biometric Fuzzy Extractor)

A Zero-Knowledge Biometric authentication system implementing a **Biometric Fuzzy Extractor** coupled with **ML-KEM-768** (FIPS 203 standardized) Post-Quantum Cryptography (PQC) and 360-degree rotation-invariant matching.

---

## 🚀 Key Features

* **Zero-Knowledge Biometric Protection:** Raw biometric features are never stored. The system operates solely on mathematical helper data ($P$) and verification hashes ($v$), ensuring user template privacy.
* **Post-Quantum Security:** Integrates lattice-based key encapsulation mechanism (**ML-KEM-768**) to establish session keys that are mathematically secure against quantum computer attacks.
* **360-Degree Rotation Invariance:** Implements a robust 10-pass orientation search ($0^\circ$ to $324^\circ$ in steps of $36^\circ$) to authenticate prints at arbitrary angles.
* **USB Sensor Support:** Configured to capture from physical USB fingerprint scanners (Mantra/Morpho local RD Services) and provides an interactive glowing visual simulator fallback.
* **Modern Dashboard UI:** Premium dark-mode dashboard styled with CSS glassmorphism, scanner line animations, and live audit logs.

---

## 📁 Repository Structure

* `app.py` — Flask server and cryptographic key agreement router.
* `database.py` — SQLite database manager for safe identities and audit logs.
* `features.py` — Fingerprint preprocessing,uint8 feature quantization, and Gabor/LBP feature extractor.
* `config.py` — Cryptographic parameters, thresholds, and upload folder configurations.
* `templates/` — HTML templates for dashboard view (`index.html`), success and error indicators.
* `.gitignore` — Excludes databases, cache directories, and temporary upload folders.

---

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone <your-repository-url>
   cd <repository-directory>
   ```

2. **Install dependencies:**
   ```bash
   pip install flask opencv-python numpy scikit-image reedsolo reportlab mlkem
   ```

3. **Run the Flask application:**
   ```bash
   python app.py
   ```
   Open your browser and navigate to `http://127.0.0.1:5001`.

---

## 🧪 Verification Tests

You can run the end-to-end verification script to automatically check SQLite migrations, enrollment, and multi-angle 1:1 and 1:N authentication:
```bash
python scratch/verify_all.py
```
