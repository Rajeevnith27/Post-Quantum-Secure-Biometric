import os
import sqlite3
import json
import time

class BiometricDatabase:
    """
    SQLite database for storing fingerprints and authentication logs with persistence.
    """
    def __init__(self, db_path='database/biometrics.db'):
        self.db_path = db_path
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        # Delete legacy JSON database files if they exist to wipe old data
        old_fp_json = os.path.join(db_dir, 'fingerprints.json')
        old_logs_json = os.path.join(db_dir, 'auth_logs.json')
        if os.path.exists(old_fp_json):
            try:
                os.remove(old_fp_json)
                print(f"Legacy cleanup: Deleted old JSON database '{old_fp_json}'")
            except Exception as e:
                print(f"Warning: Failed to delete legacy JSON file '{old_fp_json}': {e}")
        if os.path.exists(old_logs_json):
            try:
                os.remove(old_logs_json)
                print(f"Legacy cleanup: Deleted old JSON auth logs '{old_logs_json}'")
            except Exception as e:
                print(f"Warning: Failed to delete legacy JSON logs '{old_logs_json}': {e}")

        # Connect to SQLite database
        self.conn = sqlite3.connect(self.conn_str(), check_same_thread=False)
        self.create_tables()

    def conn_str(self):
        return self.db_path

    def create_tables(self):
        """Creates fingerprints and authentication logs tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fingerprints (
                fingerprint_name TEXT PRIMARY KEY,
                helper_data BLOB,
                verification_hash BLOB,
                seed BLOB,
                feature_length INTEGER,
                codeword_length INTEGER,
                pqc_public_key BLOB,
                pqc_private_key BLOB,
                fingerprint_confidence REAL,
                fingerprint_analysis TEXT,
                enrollment_timestamp REAL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                fingerprint_name TEXT,
                success INTEGER, -- 1 for success, 0 for failure
                confidence_score REAL,
                quality_score REAL,
                match_details TEXT
            )
        ''')
        self.conn.commit()

    def clear_all_data(self):
        """Wipes all enrolled fingerprints and authentication logs from the database."""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM fingerprints')
        cursor.execute('DELETE FROM auth_logs')
        self.conn.commit()
        print("Database Reset: All templates and logs cleared successfully.")

    def enroll_fingerprint(self, fingerprint_name, helper_data, verification_hash, seed, feature_length, fingerprint_confidence, fingerprint_analysis, codeword_length, pqc_public_key, pqc_private_key):
        """Adds a new fingerprint template to the SQLite database."""
        if not isinstance(fingerprint_name, str) or not fingerprint_name.strip():
            raise TypeError("fingerprint_name must be a non-empty string.")
        
        # Check if already exists
        if self.get_fingerprint_template(fingerprint_name):
            raise ValueError(f"Fingerprint '{fingerprint_name}' already exists in the database.")

        if not isinstance(helper_data, bytes) or not isinstance(verification_hash, bytes) or \
           not isinstance(seed, bytes) or \
           not isinstance(pqc_public_key, bytes) or not isinstance(pqc_private_key, bytes):
            raise TypeError("helper_data, verification_hash, seed, pqc_public_key, and pqc_private_key must be bytes.")
        if not isinstance(feature_length, int) or not isinstance(codeword_length, int):
            raise TypeError("feature_length and codeword_length must be integers.")
        if not isinstance(fingerprint_confidence, (float, int)) or not isinstance(fingerprint_analysis, dict):
            raise TypeError("fingerprint_confidence must be a number and fingerprint_analysis a dict.")

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO fingerprints (
                fingerprint_name, helper_data, verification_hash, seed, feature_length,
                codeword_length, pqc_public_key, pqc_private_key,
                fingerprint_confidence, fingerprint_analysis, enrollment_timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            fingerprint_name,
            sqlite3.Binary(helper_data),
            sqlite3.Binary(verification_hash),
            sqlite3.Binary(seed),
            feature_length,
            codeword_length,
            sqlite3.Binary(pqc_public_key),
            sqlite3.Binary(pqc_private_key),
            float(fingerprint_confidence),
            json.dumps(fingerprint_analysis),
            time.time()
        ))
        self.conn.commit()

    def get_fingerprint_template(self, fingerprint_name):
        """Retrieves a fingerprint template by name, reconstructing bytes and dicts."""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT fingerprint_name, helper_data, verification_hash, seed, feature_length,
                   codeword_length, pqc_public_key, pqc_private_key,
                   fingerprint_confidence, fingerprint_analysis, enrollment_timestamp
            FROM fingerprints WHERE LOWER(fingerprint_name) = LOWER(?)
        ''', (fingerprint_name,))
        row = cursor.fetchone()
        if not row:
            return None

        return {
            'fingerprint_name': row[0],
            'helper_data': bytes(row[1]),
            'verification_hash': bytes(row[2]),
            'seed': bytes(row[3]),
            'feature_length': row[4],
            'codeword_length': row[5],
            'pqc_public_key': bytes(row[6]),
            'pqc_private_key': bytes(row[7]),
            'fingerprint_confidence': row[8],
            'fingerprint_analysis': json.loads(row[9]) if row[9] else {},
            'enrollment_timestamp': row[10]
        }

    def get_all_fingerprint_names(self):
        """Returns a list of all enrolled fingerprint names."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT fingerprint_name FROM fingerprints')
        rows = cursor.fetchall()
        return [row[0] for row in rows]

    def get_all_auth_logs(self):
        """Returns all stored authentication logs."""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT timestamp, fingerprint_name, success, confidence_score, quality_score, match_details
            FROM auth_logs ORDER BY id ASC
        ''')
        rows = cursor.fetchall()
        logs = []
        for row in rows:
            logs.append({
                'timestamp': row[0],
                'fingerprint_name': row[1],
                'success': bool(row[2]),
                'confidence_score': row[3],
                'quality_score': row[4],
                'match_details': row[5]
            })
        return logs

    def add_auth_log(self, fingerprint_name, success, confidence_score, quality_score, details):
        """Adds an entry to the authentication log in SQLite."""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO auth_logs (timestamp, fingerprint_name, success, confidence_score, quality_score, match_details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            time.time(),
            fingerprint_name,
            1 if success else 0,
            float(confidence_score),
            float(quality_score),
            details
        ))
        self.conn.commit()

    def get_safe_fingerprint_list(self):
        """Returns enrolled fingerprints, omitting sensitive data for display."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT fingerprint_name, feature_length, fingerprint_confidence, enrollment_timestamp FROM fingerprints')
        rows = cursor.fetchall()
        safe_list = []
        for row in rows:
            safe_list.append({
                "fingerprint_name": row[0],
                "feature_length": row[1],
                "fingerprint_confidence_at_enrollment": row[2],
                "enrollment_timestamp": row[3]
            })
        return safe_list

    def delete_fingerprint(self, fingerprint_name):
        """Deletes a fingerprint template by name."""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM fingerprints WHERE fingerprint_name = ?', (fingerprint_name,))
        self.conn.commit()
        return cursor.rowcount > 0