# Post-Quantum Secure Biometric Authentication System
## Technical Architecture & Codebase Documentation

---

## 1. System Architecture Overview

This project implements a **Post-Quantum Secure Biometric Authentication Platform** combining **Fuzzy Extractor Cryptography** with **NIST FIPS 203 ML-KEM-768 (Post-Quantum Key Encapsulation)** and the **W3C Web Authentication API (WebAuthn)**. The system enables biometric enrollment and 1:1 / 1:N fingerprint authentication without storing raw biometric images, protecting templates against database compromise and quantum decryption attacks.

---

## 2. Module & File Usage Breakdown

| File / Directory | Category | Purpose & Description |
| :--- | :--- | :--- |
| **`app.py`** | Web Server / Controller | Primary Flask web server containing all HTTP routes (`/`, `/enroll`, `/authenticate`, `/logs`, `/fingerprints`, `/delete_fingerprint/<name>`, `/clear_database`). Coordinates feature extraction, fuzzy key recovery, PQC key encapsulation, and template deletion. |
| **`features.py`** | Computer Vision / Processing | Biometric processing module. Uses OpenCV and NumPy for fingerprint image normalization, Gabor filter extraction, minutiae/ridge feature vector extraction, orientation alignment, and Hamming distance calculation. |
| **`database.py`** | Data Layer | Database abstraction layer (`BiometricDatabase` class). Manages dual-mode support for local **SQLite** and cloud **PostgreSQL**, schema initialization, binary encoding (`psycopg2.Binary` vs `sqlite3.Binary`), transaction management, and logging. |
| **`config.py`** | Configuration | Centralized project settings. Defines cryptographic parameter constants (Key length = 256 bits, RS ECC symbols = 32, Fuzzy Extractor threshold = 0.85), upload path locations, and environment database URI resolving logic. |
| **`mlkem/`** | Cryptography Core | Pure Python implementation of **NIST FIPS 203 ML-KEM-768**. Contains lattice polynomial ring math, KeyGen (`generate_keypair`), Encapsulation (`encapsulate`), and Decapsulation (`decapsulate`). |
| **`scratch/verify_proofs.py`** | Security Audit CLI | Automated verification tool to evaluate Shor's lattice grid security boundaries (768-dimensions), Grover search space bounds (192-bit classical entropy), Shannon Entropy calculations of stored templates, and Reed-Solomon error correction bounds. |
| **`scratch/pqc_audit_tool.py`** | Performance Benchmark | Performance benchmarking script measuring key sizes (Public key = 1184 bytes, Ciphertext = 1088 bytes, Shared secret = 32 bytes) and execution timings against FIPS 203 standards. |
| **`scratch/tamper_test.py`** | Security Tester | Terminal simulator tool that mocks database template corruptions (XOR bit flips on helper data, hashes, and PQC keys) to verify that tampered records fail authentication securely. |
| **`templates/base_style.html`** | UI Design System | Central CSS style system implementing the Slate & Sky-Blue palette (`#0F172A`, `#1E293B`, `#2563EB`, `#0EA5E9`), glassmorphic panels, button gradients, and responsive layout grids. |
| **`templates/index.html`** | Main Dashboard | Primary user interface template. Features the tabbed navigation system (Biometric Scanner, Enrolled Users List, Audit Logs Table, and System Configuration). Integrates WebAuthn browser APIs for hardware biometric device capture. |
| **`templates/success.html`** | UI View | Authentication success page displaying handshake details, orientation alignment match, reconstructed keys ($R$), PQC ciphertext ($c_{pqc}$), and shared session secret ($K_{session}$). |
| **`templates/error.html`** | UI View | Error rendering page displaying failure messages, rejection reasons, and back navigation controls. |
| **`templates/delete_success.html`** | UI View | Confirmation view rendered upon successful user template deletion from the database. |

---

## 3. Third-Party Libraries & Dependencies

| Library Name | Import Name | Purpose in Codebase |
| :--- | :--- | :--- |
| **Flask** | `flask` | Lightweight WSGI web application framework used to build server routes, handle HTTP POST multipart form uploads, render HTML templates, and return JSON responses. |
| **OpenCV** | `cv2` (`opencv-python`) | Computer vision library used in `features.py` for image loading, resizing, Gaussian blurring, adaptive thresholding, morphological thinning, and Gabor filtering. |
| **NumPy** | `numpy` | Fundamental array computing library used in `features.py` for high-performance bitwise XOR, Hamming distance calculations, matrix manipulation, and feature vector alignment. |
| **reedsolo** | `reedsolo` | Third-party implementation of **Reed-Solomon Error Correction Codec (RSCodec)**. Used in the Fuzzy Extractor phase to produce parity symbols during enrollment and recover secret key $R$ from noisy biometric scans. |
| **psycopg2-binary** | `psycopg2` | PostgreSQL database adapter for Python. Enables seamless integration with cloud relational databases (e.g., Render PostgreSQL). |
| **Semgrep** | `semgrep` | Third-party Static Application Security Testing (SAST) tool used to scan Python files and HTML templates for OWASP top 10 security vulnerabilities. |

---

## 4. Third-Party APIs, Web Standards & CDNs

| Service / API | Type | Purpose in Application |
| :--- | :--- | :--- |
| **W3C Web Authentication API (WebAuthn)** | Web Browser Standard API | JavaScript browser API (`navigator.credentials`) used to interface with hardware biometric authenticators (Touch ID, Face ID, Windows Hello, and FIDO2 keys). |
| **Google Fonts API** | Web Font CDN | Loads the **Inter** (`sans-serif`) and **JetBrains Mono** (`monospace`) typography stylesheets for UI layout rendering. |
| **Render Cloud Environment API** | Infrastructure Hosting | Automatically injects the `DATABASE_URL` environment variable to switch the database driver from local SQLite to cloud PostgreSQL during deployment. |

---

## 5. Built-in Python Standard Libraries Used

* **`os`**: File path management and environment variable retrieval (`os.environ.get`).
* **`sqlite3`**: Default embedded database engine for offline local execution.
* **`hashlib`**: Cryptographic hash functions (`hashlib.sha256`) for generating verification hashes $v = \text{SHA256}(R)$.
* **`secrets` / `urandom`**: Cryptographically secure random number generation for key seeds and noise vectors.
* **`datetime`**: Generating human-readable timestamps for enrollment and authentication audit logs.
* **`json`**: Formatted JSON data serialization for AJAX frontend communication.
* **`math`**: Trigonometric calculations for fingerprint ridge orientation and Gabor filter kernels.

---

## 6. Copyright Notice

© 2026 Rajeev Ranjan, NIT Hamirpur. All Rights Reserved.
