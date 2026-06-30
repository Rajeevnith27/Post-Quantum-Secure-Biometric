# Technical Guide: Biometric Fuzzy Extractor & Post-Quantum Cryptography

This document explains the step-by-step technical workflow of the system's **Zero-Knowledge Biometric Fuzzy Extractor** and **ML-KEM-768 Post-Quantum Key Agreement** in simple terms, suitable for sharing with peers, clients, or team members.

---

## 💡 The Core Concepts (The Analogy)

* **Traditional Passwords are Rigid:** If you set a password to `Security123` and type `security123` (lowercase 's'), access is denied. Traditional security requires a **100% exact match**.
* **Biometrics are Fuzzy:** You can never scan your finger the exact same way twice. Dry skin, pressure, sweat, cuts, and rotation cause the extracted data to change slightly with every scan.
* **The Fuzzy Extractor (The Solution):** It acts as a "biometric translator." It uses advanced mathematical error-correction (similar to how CDs clean up scratches) to reconstruct the **exact same digital key** from a noisy fingerprint scan.
* **Zero-Knowledge Templates:** To protect user privacy, **the database never stores raw fingerprints or feature templates**. It only stores a mathematical puzzle (Helper Data) and a verification stamp (Hash). If a hacker steals the database, they cannot recreate your fingerprint.

---

## 🔑 Phase 1: Enrollment (User Registration)

Enrollment creates a secure mathematical puzzle (Helper Data) and registers it on the server.

```
[Fingerprint Scan] ──> [Extract Features (X)]
                             │
                             ▼
  [Random Key (K)] ──> [Codeword (C)] ──> [XOR with X] ──> [Helper Data (P)] ──> Save to DB
                             │
                             ▼
                         [Hash (v)] ───────────────────────────────────────────> Save to DB
```

* **Step 1: Fingerprint Capture**
  The user places their finger on the sensor. The system captures the raw fingerprint image.
* **Step 2: Feature Extraction**
  The image is analyzed to extract a 71-byte list of numbers representing the ridges, textures, and directions (Features $X$). These numbers are quantized to uint8 integers to smooth out minor sub-pixel variations.
* **Step 3: Random Key Generation**
  The system generates a completely random secret key $K$ (think of this as the core cryptographic key).
* **Step 4: Codeword Encoding**
  The key $K$ is expanded into a 120-byte Reed-Solomon Codeword ($C$). This codeword has built-in redundancy, allowing it to survive up to 30 errors (corrupted or changed bytes).
* **Step 5: Puzzle Creation (Helper Data $P$)**
  The system locks the codeword $C$ using the fingerprint features $X$ via a bitwise XOR operation:
  $$P = C \oplus X$$
  *The resulting $P$ is called **Helper Data**. On its own, it looks like complete random noise and reveals nothing about the user's fingerprint.*
* **Step 6: Verification Hash**
  The key $K$ is run through SHA-256 to create a verification hash $v = H(R)$. This acts as a stamp to verify if a reconstructed key is correct without storing the key itself.
* **Step 7: Post-Quantum Keypair Generation**
  The system generates an **ML-KEM-768** keypair (a Public key and a Private key). ML-KEM uses lattice-based mathematics that quantum computers cannot crack.
* **Step 8: Save & Purge**
  * **Saved in DB:** The Helper Data ($P$), the Verification Hash ($v$), and the PQC keypair.
  * **Destroyed:** The raw fingerprint image and extracted features $X$ are **deleted permanently from memory**.

---

## 🔒 Phase 2: Authentication (Login & Session Key Agreement)

Authentication uses the user's finger to unlock the stored puzzle, verify identity, and establish a quantum-safe session key.

```
[New Scan] ──> [New Features (X')] ──> [Rotate 10 times]
                                             │
                                             ▼
  [Helper Data (P)] ──[XOR with X'] ──> [Codeword (C')]
                                             │
                                             ▼
                                     [Error Correction] ──> [Recovered Key (K')]
                                                                    │
                                                                    ▼
                                                             [Hash & Compare] ──> Match? ──> Granted
```

* **Step 1: Fresh Capture**
  The user places their finger on the scanner. The system extracts a new feature list $X'$. Due to noise and placement, $X'$ is slightly different from the original $X$ (e.g., 10–15 bytes differ).
* **Step 2: 10-Orientation Search**
  To handle upside-down or tilted finger placement, the system generates 10 rotated variations of $X'$ spaced by 36 degrees.
* **Step 3: Codeword Reconstruction**
  For each angle, the system XORs the candidate features with the stored Helper Data $P$ to attempt codeword reconstruction:
  $$C' = P \oplus X'_{rotated}$$
* **Step 4: Error Correction**
  The system feeds $C'$ into the Reed-Solomon decoder. If the orientation is correct, the decoder corrects the differences (up to 30 byte errors) and recovers the **exact original secret key $K$**.
* **Step 5: Cryptographic Stamp Check**
  The recovered key is hashed and compared against the stored verification hash $v$. If it matches, the user's identity is mathematically proven.
* **Step 6: Post-Quantum Encapsulation**
  The server takes the user's stored ML-KEM-768 public key and generates a shared secret ($ss$) and encrypts it inside a ciphertext box ($c$).
* **Step 7: Post-Quantum Decapsulation**
  The client uses its private key to decrypt $c$ and recover $ss$.
* **Step 8: Final Session Key derivation**
  Both sides combine the biometric key and the post-quantum secret to form the final quantum-safe session key:
  $$K_{session} = \text{SHA-256}(R \mathbin{\Vert} ss)$$
  *Even if an eavesdropper records all network traffic today, a future quantum computer cannot decrypt the communication.*
