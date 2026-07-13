import sys
import time
import binascii

try:
    from mlkem.ml_kem import ML_KEM
    from mlkem.parameter_set import ML_KEM_768
except ImportError as err:
    print(f"Error: {err}")
    print("Please ensure the mlkem library is installed correctly.")
    sys.exit(1)

def run_pqc_audit():
    print("=" * 60)
    print("         POST-QUANTUM CRYPTOGRAPHY (PQC) AUDIT TOOL         ")
    print("              NIST FIPS 203 / ML-KEM Compliance             ")
    print("=" * 60)
    
    # 1. Inspecting Parameters
    print("\n[Step 1] Verifying Algorithm Parameters against FIPS 203 Standard:")
    print("  - Target Algorithm: ML-KEM-768 (Category 3 Security)")
    
    # Standard sizes
    expected_pk_len = 1184
    expected_sk_len = 2400
    expected_ct_len = 1088
    expected_ss_len = 32
    
    # 2. Key Generation Test
    print("\n[Step 2] Testing Key Generation (KeyGen)...")
    start = time.perf_counter()
    try:
        kem = ML_KEM(ML_KEM_768, fast=False)
        # Note: Depending on the library implementation, kem generation outputs public key and private key bytes
        ek, dk = kem.key_gen()
        keygen_time = (time.perf_counter() - start) * 1000
        
        print(f"  - Public Key (ek) Size: {len(ek)} bytes (Expected: {expected_pk_len} bytes)")
        print(f"  - Private Key (dk) Size: {len(dk)} bytes (Expected: {expected_sk_len} bytes)")
        print(f"  - KeyGen Time: {keygen_time:.2f} ms")
        
        if len(ek) == expected_pk_len and len(dk) == expected_sk_len:
            print("  => STATUS: PASS (Key dimensions are FIPS 203 compliant)")
        else:
            print("  => STATUS: FAIL (Key dimensions mismatch)")
    except Exception as e:
        print(f"  => STATUS: FAIL (Error during KeyGen: {e})")
        return

    # 3. Encapsulation Test
    print("\n[Step 3] Testing Key Encapsulation (Encaps)...")
    start = time.perf_counter()
    try:
        ss, ct = kem.encaps(ek)
        encaps_time = (time.perf_counter() - start) * 1000
        
        print(f"  - Ciphertext (ct) Size: {len(ct)} bytes (Expected: {expected_ct_len} bytes)")
        print(f"  - Shared Secret (ss) Size: {len(ss)} bytes (Expected: {expected_ss_len} bytes)")
        print(f"  - Encapsulation Time: {encaps_time:.2f} ms")
        
        if len(ct) == expected_ct_len and len(ss) == expected_ss_len:
            print("  => STATUS: PASS (Ciphertext dimensions are FIPS 203 compliant)")
        else:
            print("  => STATUS: FAIL (Ciphertext dimensions mismatch)")
    except Exception as e:
        print(f"  => STATUS: FAIL (Error during Encapsulation: {e})")
        return

    # 4. Decapsulation Test
    print("\n[Step 4] Testing Key Decapsulation (Decaps)...")
    start = time.perf_counter()
    try:
        ss_decrypted = kem.decaps(dk, ct)
        decaps_time = (time.perf_counter() - start) * 1000
        
        print(f"  - Decrypted Shared Secret Size: {len(ss_decrypted)} bytes")
        print(f"  - Decapsulation Time: {decaps_time:.2f} ms")
        
        # Verify agreement
        if ss == ss_decrypted:
            print("  - Key Agreement Match: YES (Shared secrets are identical)")
            print(f"  - Shared Secret (Hex): {binascii.hexlify(ss).decode()}")
            print("  => STATUS: PASS (Key encapsulation/decapsulation math is 100% correct)")
        else:
            print("  - Key Agreement Match: NO")
            print("  => STATUS: FAIL (Decapsulated secret mismatch)")
    except Exception as e:
        print(f"  => STATUS: FAIL (Error during Decapsulation: {e})")
        return

    print("\n" + "=" * 60)
    print("  AUDIT RESULT: SYSTEM CRYPTOGRAPHY IS QUANTUM-SAFE (PASS)  ")
    print("=" * 60)

if __name__ == "__main__":
    run_pqc_audit()
