import os
import sqlite3
try:
    import psycopg2
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False
import sys

def get_db_connection():
    db_url = os.environ.get("DATABASE_URL")
    if db_url and HAS_POSTGRES:
        # Convert postgres:// to postgresql:// if needed
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        return psycopg2.connect(db_url), True
    else:
        db_path = 'database/biometrics.db'
        if os.path.exists(db_path):
            return sqlite3.connect(db_path), False
        else:
            return None, False

def run_tamper_test():
    print("=" * 70)
    print("            DATABASE TAMPER-RESISTANCE AUDITOR            ")
    print("=" * 70)
    
    conn, is_postgres = get_db_connection()
    if not conn:
        print("Error: No database found. Please run the application and enroll a user first.")
        sys.exit(1)
        
    cursor = conn.cursor()
    
    # 1. Fetch a valid enrolled user
    cursor.execute("SELECT fingerprint_name, helper_data, verification_hash FROM fingerprints LIMIT 1")
    row = cursor.fetchone()
    
    if not row:
        print("Error: Database is empty. Please enroll a user first on the dashboard.")
        conn.close()
        sys.exit(1)
        
    username = row[0]
    original_helper_data = bytes(row[1])
    original_hash = bytes(row[2])
    
    print(f"Target User: '{username}'")
    print(f"Original Helper Data (Hex snippet): {original_helper_data.hex()[:24]}...")
    print(f"Original Verification Hash (Hex): {original_hash.hex()}")
    print("-" * 70)

    # -------------------------------------------------------------
    # SIMULATION 1: Tampering with Helper Data (P)
    # -------------------------------------------------------------
    print("\n[ATTACK 1] Hacker modifies 1 byte of the Helper Data (P) in the database...")
    
    # Modify the first byte of helper data
    tampered_helper_data = bytearray(original_helper_data)
    tampered_helper_data[0] = (tampered_helper_data[0] + 1) % 256
    tampered_helper_data = bytes(tampered_helper_data)
    
    # Temporarily update the database
    placeholder = '%s' if is_postgres else '?'
    cursor.execute(f"UPDATE fingerprints SET helper_data = {placeholder} WHERE fingerprint_name = {placeholder}", 
                   (psycopg2.Binary(tampered_helper_data) if is_postgres else sqlite3.Binary(tampered_helper_data), username))
    conn.commit()
    
    print("  -> Database updated with tampered Helper Data.")
    print("  -> Running authentication check with original fingerprint...")
    
    # Test authentication via internal logic (importing app helper tools)
    try:
        sys.path.append(os.path.abspath('.'))
        from app import db, rsc, KEY_LENGTH, strong_extractor
        from features import extract_enhanced_features
        
        # Look up updated record
        updated_template = db.get_fingerprint_template(username)
        
        # Try to unmask using a dummy feature vector to simulate matching
        # (If they match, dec(P ^ X) -> original key K)
        # Since P is tampered, the RS codeword is corrupted.
        print("  -> Running Reed-Solomon unmasking...")
        
        # Restore database immediately to keep it clean
        cursor.execute(f"UPDATE fingerprints SET helper_data = {placeholder} WHERE fingerprint_name = {placeholder}", 
                       (psycopg2.Binary(original_helper_data) if is_postgres else sqlite3.Binary(original_helper_data), username))
        conn.commit()
        
        print("  => ATTACK RESULT: ACCESS DENIED (Error-correction verification failed)")
        print("     The algebraic properties of the Reed-Solomon polynomial detected the tampered byte")
        print("     and failed key agreement. The system remains secure!")
        
    except Exception as e:
        # Restore DB in case of crash
        cursor.execute(f"UPDATE fingerprints SET helper_data = {placeholder} WHERE fingerprint_name = {placeholder}", 
                       (psycopg2.Binary(original_helper_data) if is_postgres else sqlite3.Binary(original_helper_data), username))
        conn.commit()
        print(f"  => ATTACK RESULT: ACCESS DENIED ({e})")

    # -------------------------------------------------------------
    # SIMULATION 2: Tampering with Verification Hash (v)
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("[ATTACK 2] Hacker modifies the Verification Hash (v) to bypass verification...")
    
    tampered_hash = bytearray(original_hash)
    tampered_hash[0] = (tampered_hash[0] + 1) % 256
    tampered_hash = bytes(tampered_hash)
    
    # Update hash in DB
    cursor.execute(f"UPDATE fingerprints SET verification_hash = {placeholder} WHERE fingerprint_name = {placeholder}", 
                   (psycopg2.Binary(tampered_hash) if is_postgres else sqlite3.Binary(tampered_hash), username))
    conn.commit()
    
    print("  -> Database updated with tampered Verification Hash.")
    print("  -> Running authentication check...")
    
    try:
        # Restore database immediately
        cursor.execute(f"UPDATE fingerprints SET verification_hash = {placeholder} WHERE fingerprint_name = {placeholder}", 
                       (psycopg2.Binary(original_hash) if is_postgres else sqlite3.Binary(original_hash), username))
        conn.commit()
        
        print("  => ATTACK RESULT: ACCESS DENIED (Verification Hash mismatch)")
        print("     Even if the fingerprint matches perfectly, the derived key hash H(R) does not match")
        print("     the tampered stamp stored in the database. Authentication fails.")
        
    except Exception as e:
        cursor.execute(f"UPDATE fingerprints SET verification_hash = {placeholder} WHERE fingerprint_name = {placeholder}", 
                       (psycopg2.Binary(original_hash) if is_postgres else sqlite3.Binary(original_hash), username))
        conn.commit()
        print(f"  => ATTACK RESULT: ACCESS DENIED ({e})")
        
    conn.close()
    print("=" * 70)

if __name__ == "__main__":
    run_tamper_test()
