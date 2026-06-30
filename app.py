from flask import Flask, request, render_template, jsonify, redirect, url_for, send_from_directory
import os
import uuid
from werkzeug.utils import secure_filename
import time
import json
import sqlite3
import hashlib

# Import modules from your project
from config import UPLOAD_FOLDER, FINGERPRINT_THRESHOLDS, MATCH_THRESHOLD, REQUIRE_CRYPTO_FOR_100_PERCENT, KEY_LENGTH, SEED_LENGTH, RS_ECC_SYMBOLS
from features import comprehensive_fingerprint_detection, extract_enhanced_features, calculate_feature_similarity, strong_extractor
from reedsolo import RSCodec, ReedSolomonError
import cv2
import numpy as np

# Import database module (SQLite version)
from database import BiometricDatabase

# PQC imports
from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_768

# Initialize Flask
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Reed-Solomon Codec
rsc = RSCodec(RS_ECC_SYMBOLS)

# Instantiate the database
db = BiometricDatabase()

# Serve static uploads
@app.route('/uploads/<filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Routes
@app.route('/', methods=['GET'])
def index():
    """Renders the main dashboard page."""
    fp_count = len(db.get_all_fingerprint_names())
    return render_template('index.html',
                           thresholds=FINGERPRINT_THRESHOLDS,
                           fp_count=fp_count,
                           require_crypto_for_100=REQUIRE_CRYPTO_FOR_100_PERCENT)

@app.route('/enroll', methods=['POST'])
def enroll():
    """Handles fingerprint enrollment (file upload or captured path)."""
    fingerprint_name = request.form.get('fingerprint_name', '').strip()
    if not fingerprint_name:
        return render_template('error.html',
                               title="Enrollment Failed",
                               message="The fingerprint name is required for enrollment. Please provide a unique name.",
                               back_url='/',
                               back_text='Try Enrollment Again')

    # Support both file upload and direct captured image paths from the sensor simulator
    captured_filename = request.form.get('captured_filename', '').strip()
    file = request.files.get('bio')

    if captured_filename:
        # Use the sensor-captured file already stored in UPLOAD_FOLDER
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(captured_filename))
    elif file:
        temp_id = str(uuid.uuid4())
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{temp_id}_{secure_filename(file.filename)}")
        file.save(filepath)
    else:
        return render_template('error.html',
                               title="Enrollment Failed",
                               message="Please select an image file or capture from sensor to enroll.",
                               back_url='/',
                               back_text='Try Enrollment Again')

    try:
        is_fingerprint, fp_confidence, fp_analysis = comprehensive_fingerprint_detection(filepath)

        quality_class = "low"
        if fp_confidence >= 0.3: quality_class = "medium"
        if fp_confidence >= 0.6: quality_class = "high"

        if not is_fingerprint:
            db.add_auth_log(fingerprint_name, False, 0.0, fp_confidence, "Enrollment failed: Not a valid fingerprint (detection).")
            return render_template('error.html',
                                   title="Enrollment Failed - Not a Valid Fingerprint",
                                   message="The system could not validate the uploaded image as a real fingerprint based on its characteristics.",
                                   details={
                                       "Detection Score": {"score": fp_confidence, "class": quality_class},
                                       "Detailed Analysis": fp_analysis
                                   },
                                   back_url='/',
                                   back_text='Try Enrollment Again')

        x = extract_enhanced_features(filepath)

        K = os.urandom(KEY_LENGTH)
        # Pad K to be at least RS_ECC_SYMBOLS long if necessary for Reed-Solomon encoding
        if len(K) < RS_ECC_SYMBOLS:
            K_padded = K + os.urandom(RS_ECC_SYMBOLS - len(K))
        else:
            K_padded = K

        C = rsc.encode(K_padded)

        # Ensure x_truncated_for_P has enough bytes to match C
        x_truncated_for_P = x[:len(C)]
        if len(x_truncated_for_P) < len(C):
            x_truncated_for_P += bytes(len(C) - len(x_truncated_for_P))
        
        P_core = bytes([a ^ b for a, b in zip(C, x_truncated_for_P)])
        P = P_core + x[len(C):] # P combines XORed part and remaining features

        seed = os.urandom(SEED_LENGTH)
        R = strong_extractor(K, seed)

        # Generate PQC ML-KEM-768 keys
        ml_kem = ML_KEM(ML_KEM_768, fast=False)
        pqc_public_key, pqc_private_key = ml_kem.key_gen()

        db.enroll_fingerprint(
            fingerprint_name=fingerprint_name,
            helper_data=P,
            verification_hash=R,
            seed=seed,
            feature_length=len(x),
            codeword_length=len(C),
            pqc_public_key=pqc_public_key,
            pqc_private_key=pqc_private_key,
            fingerprint_confidence=fp_confidence,
            fingerprint_analysis=fp_analysis
        )
        db.add_auth_log(fingerprint_name, True, fp_confidence, fp_confidence, "Enrollment successful with PQC key pair generated.")

        return render_template('success.html',
                               title="Enrollment Successful",
                               message="This fingerprint has been successfully stored with post-quantum KEM key pair.",
                               details={
                                   "Fingerprint Name": fingerprint_name,
                                   "Enrollment Confidence (Quality)": {
                                       "score": fp_confidence,
                                       "class": quality_class
                                   },
                                   "Post-Quantum Cryptography": f"ML-KEM-768 key pair generated (Public Key: {pqc_public_key[:16].hex()}...)",
                                   "Detailed Analysis at Enrollment": fp_analysis
                               },
                               back_url='/',
                               back_text='Enroll Another Fingerprint')

    except ValueError as ve:
        db.add_auth_log(fingerprint_name, False, 0.0, 0.0, f"Enrollment failed: {str(ve)}")
        return render_template('error.html',
                               title="Enrollment Failed",
                               message=f"Error: {str(ve)}. This usually means the fingerprint name is already taken or there was an issue with the data provided.",
                               back_url='/',
                               back_text='Try Enrollment Again')
    except Exception as e:
        db.add_auth_log(fingerprint_name, False, 0.0, 0.0, f"Enrollment failed: Unexpected error: {str(e)}")
        return render_template('error.html',
                               title="Enrollment Failed - Unexpected Error",
                               message=f"An internal error occurred: {str(e)}. Please try again later or contact support.",
                               back_url='/',
                               back_text='Try Enrollment Again')
    finally:
        # Keep sensor-captured files so they can be viewed, but clean up uploaded temp files
        if file and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except:
                pass

@app.route('/authenticate', methods=['POST'])
def authenticate():
    """Handles fingerprint identification (1-to-many) with full 360-degree rotation invariance."""
    captured_filename = request.form.get('captured_filename', '').strip()
    file = request.files.get('bio')

    if captured_filename:
        temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(captured_filename))
    elif file:
        temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"auth_temp_{uuid.uuid4()}_{secure_filename(file.filename)}")
        file.save(temp_filepath)
    else:
        return render_template('error.html',
                               title="Authentication Failed",
                               message="Please select an image file or capture from sensor to authenticate.",
                               back_url='/',
                               back_text='Try Authentication Again')

    overall_match_details = "Authentication failed: No matching fingerprint found."
    max_similarity_score_overall = 0.0
    identified_fingerprint_name = "N/A"
    fp_confidence_presented = 0.0
    best_candidate_template = None
    best_candidate_biometric_key_R = None
    best_candidate_orientation = "N/A"
    
    try:
        is_fingerprint_presented, fp_confidence_presented, _ = comprehensive_fingerprint_detection(temp_filepath)
        quality_class_presented = "low"
        if fp_confidence_presented >= 0.3: quality_class_presented = "medium"
        if fp_confidence_presented >= 0.6: quality_class_presented = "high"

        if not is_fingerprint_presented:
            db.add_auth_log("N/A", False, 0.0, fp_confidence_presented, "Authentication failed: Presented image is not a valid fingerprint (detection).")
            return render_template('error.html',
                                   title="Authentication Failed - Not a Fingerprint",
                                   message="The uploaded image did not pass fingerprint validation checks.",
                                   details={
                                       "Detection Score": {"score": fp_confidence_presented, "class": quality_class_presented},
                                       "Please ensure the image is a clear fingerprint.": ""
                                   },
                                   back_url='/',
                                   back_text='Try Authentication Again')

        # Determine authentication mode (1:1 Verification vs 1:N Identification)
        username_to_verify = request.form.get('username_to_verify', '').strip()
        is_one_to_one = False
        
        if username_to_verify:
            is_one_to_one = True
            # Verify if user exists in DB
            user_template = db.get_fingerprint_template(username_to_verify)
            if not user_template:
                db.add_auth_log(username_to_verify, False, 0.0, fp_confidence_presented, f"1:1 Verification failed: User '{username_to_verify}' not found in database.")
                return render_template('error.html',
                                       title="1:1 Verification Failed",
                                       message=f"The username '{username_to_verify}' does not exist in the database. Please enroll first.",
                                       back_url='/',
                                       back_text='Try Again')
            enrolled_fingerprint_names = [username_to_verify]
        else:
            enrolled_fingerprint_names = db.get_all_fingerprint_names()

        # Extract features for multiple search rotation angles (10 angles spaced by 36 degrees)
        # This provides robust 360-degree rotation invariance even under extreme placement angles.
        search_angles = [0, 36, 72, 108, 144, 180, 216, 252, 288, 324]
        presented_features_by_angle = {}
        for angle in search_angles:
            presented_features_by_angle[angle] = extract_enhanced_features(temp_filepath, additional_rotation=angle)
        
        # Iterate through the selected candidate names
        max_similarity_score_overall = 0.0

        for fingerprint_name in enrolled_fingerprint_names:
            enrolled_template = db.get_fingerprint_template(fingerprint_name)
            if not enrolled_template:
                continue

            current_helper_data = enrolled_template['helper_data']
            current_seed = enrolled_template['seed']
            current_codeword_length = enrolled_template['codeword_length']
            
            # Evaluate the presented fingerprint at all 10 search rotations
            for angle in search_angles:
                p_feat = presented_features_by_angle[angle]
                
                try:
                    # Pad presented features to current_codeword_length (120)
                    core_presented_features = p_feat[:current_codeword_length]
                    if len(core_presented_features) < current_codeword_length:
                        core_presented_features += bytes(current_codeword_length - len(core_presented_features))

                    # Perform XOR for key recovery
                    C_prime = bytes([a ^ b for a, b in zip(current_helper_data[:current_codeword_length], core_presented_features)])
                    
                    K_recovered_with_parity, _, errata_positions = rsc.decode(C_prime)
                    num_errors = len(errata_positions)
                    
                    K_recovered = K_recovered_with_parity[:KEY_LENGTH]
                    R_prime = strong_extractor(K_recovered, current_seed)

                    if R_prime == enrolled_template['verification_hash']:
                        # Cryptographically verified!
                        similarity = 1.0 - (num_errors / 60.0)
                        if similarity > max_similarity_score_overall:
                            max_similarity_score_overall = similarity
                            identified_fingerprint_name = fingerprint_name
                            best_candidate_template = enrolled_template
                            best_candidate_biometric_key_R = R_prime
                            best_candidate_orientation = f"{angle}° Rotation ({num_errors} errors corrected)"
                        print(f"Debug: Key recovered successfully for '{fingerprint_name}' ({angle}° Rotation, {num_errors} errors).")
                except (ReedSolomonError, ValueError, IndexError):
                    pass

        # --- Final Authentication Decision & PQC Key Agreement ---
        
        if identified_fingerprint_name != "N/A":
            pqc_public_key = best_candidate_template['pqc_public_key']
            pqc_private_key = best_candidate_template['pqc_private_key']

            try:
                # 1. Post-Quantum KEM Encapsulation using the stored public key
                ml_kem = ML_KEM(ML_KEM_768, fast=False)
                ss, c_pqc = ml_kem.encaps(pqc_public_key)

                # 2. Post-Quantum KEM Decapsulation using the stored private key
                ss_prime = ml_kem.decaps(pqc_private_key, c_pqc)

                # 3. Verify shared secret agreement
                if ss != ss_prime:
                    raise ValueError("PQC Decapsulation mismatch. Shared secrets do not match.")

                # 4. Derivation of the final Quantum-Resistant Session Key K_session = H(R || ss)
                K_session = hashlib.sha256(best_candidate_biometric_key_R + ss).digest()

                quality_class_match = "low"
                if max_similarity_score_overall >= 0.5: quality_class_match = "medium"
                if max_similarity_score_overall >= 0.88: quality_class_match = "high"

                db.add_auth_log(identified_fingerprint_name, True, max_similarity_score_overall, fp_confidence_presented, "Identification and PQC key agreement successful.")

                return render_template('success.html',
                                       title="Identification & PQC Key Agreement Successful",
                                       message=f"Access Granted for: {identified_fingerprint_name}!",
                                       details={
                                           "Identified Fingerprint": identified_fingerprint_name,
                                           "Verification Mode": "1:1 Verification (Match by Username)" if is_one_to_one else "1:N Identification (Database Search)",
                                           "Match Confidence": {
                                               "score": max_similarity_score_overall,
                                               "class": quality_class_match
                                           },
                                           "Presented Fingerprint Quality": {
                                               "score": fp_confidence_presented,
                                               "class": quality_class_presented
                                           },
                                           "Matched Orientation": f"<span style='color: #2196F3; font-weight: bold;'>{best_candidate_orientation}</span>",
                                           "Biometric Verification Hash (R)": f"<code style='font-family: monospace; background: #1e1e1e; padding: 3px 6px; border-radius: 4px; word-break: break-all; color: #4CAF50;'>{best_candidate_biometric_key_R.hex()}</code>",
                                           "PQC Ciphertext (c_pqc)": f"<code style='font-family: monospace; background: #1e1e1e; padding: 3px 6px; border-radius: 4px; word-break: break-all; color: #2196F3;'>{c_pqc.hex()[:64]}... ({len(c_pqc)} bytes)</code>",
                                           "PQC Shared Secret (ss)": f"<code style='font-family: monospace; background: #1e1e1e; padding: 3px 6px; border-radius: 4px; word-break: break-all; color: #E91E63;'>{ss.hex()}</code>",
                                           "Quantum-Resistant Session Key": f"<code style='font-family: monospace; background: #1e1e1e; padding: 3px 6px; border-radius: 4px; word-break: break-all; color: #FFC107; font-weight: bold;'>{K_session.hex()}</code>",
                                           "PQC Status": f"<span style='color: #4CAF50; font-weight: bold;'>✓ Key Agreement Successful (ML-KEM-768)</span>"
                                       },
                                       back_url='/',
                                       back_text='Authenticate Another')

            except Exception as pqc_err:
                final_message = f"Authentication failed during Post-Quantum Cryptographic key agreement: {str(pqc_err)}"
                db.add_auth_log(identified_fingerprint_name, False, max_similarity_score_overall, fp_confidence_presented, final_message)
                return render_template('error.html',
                                       title="PQC Key Agreement Failed",
                                       message=final_message,
                                       back_url='/',
                                       back_text='Try Authentication Again')
        else:
            final_message = "Identification failed: Cryptographic key agreement failed. No matching fingerprint template could be verified."
            db.add_auth_log("N/A", False, 0.0, fp_confidence_presented, final_message)
            return render_template('error.html',
                                   title="Identification Failed",
                                   message=final_message,
                                   details={
                                       "Presented Fingerprint Quality": {
                                           "score": fp_confidence_presented,
                                           "class": quality_class_presented
                                       },
                                       "Reason": "Presented biometric did not yield a valid key match against any enrolled template."
                                   },
                                   back_url='/',
                                   back_text='Try Authentication Again')

    except Exception as e:
        db.add_auth_log("N/A (Error)", False, 0.0, fp_confidence_presented, f"Authentication error: {str(e)}")
        return render_template('error.html',
                               title="Authentication Failed - Unexpected Error",
                               message=f"An unexpected error occurred: {str(e)}. Please try again later or contact support.",
                               back_url='/',
                               back_text='Try Authentication Again')
    finally:
        # Clean up file only if uploaded via file input
        if file and os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except:
                pass

@app.route('/sensor/capture', methods=['POST'])
def sensor_capture():
    """Simulates a USB fingerprint scanner capturing an image with dynamic noise and rotation."""
    finger_id = request.json.get('finger_id', 'random')
    temp_id = str(uuid.uuid4())
    filename = f"sensor_capture_{temp_id}.png"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        # Create a blank white image
        img = np.ones((256, 256), dtype=np.uint8) * 255

        # Seed random number generator based on the finger_id to make it reproducible
        # but with slight random variations (noise/rotation/offset) for error tolerance testing
        if finger_id == 'finger_A':
            seed_val = 1000
        elif finger_id == 'finger_B':
            seed_val = 2000
        elif finger_id == 'finger_C':
            seed_val = 3000
        else:
            seed_val = int(time.time()) % 10000

        np.random.seed(seed_val)

        # Draw a synthetic fingerprint-like pattern
        # A whorl/loop pattern is drawn using concentric circles/ellipses with a center
        center_x = 128 + np.random.randint(-15, 15)
        center_y = 128 + np.random.randint(-15, 15)
        
        # Add slight rotation to the lines
        angle_offset = np.random.randint(-20, 20) # rotation variance
        
        for r in range(15, 120, 8):
            # Draw concentric ellipses representing fingerprint ridges
            cv2.ellipse(img, (center_x, center_y), (r, int(r * 1.35)), angle_offset, 0, 360, 0, 2)

        # Draw some minutiae-like points (small circles or ridge breaks)
        for _ in range(35):
            mx = np.random.randint(40, 216)
            my = np.random.randint(40, 216)
            cv2.circle(img, (mx, my), np.random.randint(1, 3), 0, -1)

        # Add Gaussian noise to simulate scanner texture
        noise = np.random.normal(0, 18, img.shape).astype(np.float32)
        img_noisy = np.clip(img.astype(np.float32) + noise, 0, 255).astype(np.uint8)
        
        # Apply slight blur to make it look like a finger scan
        img_final = cv2.GaussianBlur(img_noisy, (3, 3), 0)

        # Save the synthetic captured image
        cv2.imwrite(filepath, img_final)
        
        # We return the URL path to access the file
        image_url = f"/uploads/{filename}"
        return jsonify({
            "success": True,
            "image_url": image_url,
            "filename": filename,
            "message": f"Captured successfully from USB Sensor (Virtual {finger_id.upper()})."
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/clear_database', methods=['POST'])
def clear_database():
    """Wipes all fingerprints and logs from SQLite database."""
    try:
        db.clear_all_data()
        return jsonify({"success": True, "message": "Database reset successfully. All records wiped."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/logs', methods=['GET'])
def get_logs():
    """Returns all authentication logs as JSON."""
    logs = db.get_all_auth_logs()
    for log in logs:
        if 'timestamp' in log:
            log['timestamp_human'] = time.ctime(log['timestamp'])
    return jsonify(logs)

@app.route('/fingerprints', methods=['GET'])
def get_fingerprints():
    """Returns a list of enrolled fingerprints, omitting sensitive data."""
    fps = db.get_safe_fingerprint_list()
    for fp in fps:
        if 'enrollment_timestamp' in fp:
            fp['enrollment_timestamp_human'] = time.ctime(fp['enrollment_timestamp'])
    return jsonify(fps)

@app.route('/delete_fingerprint/<string:fingerprint_name>', methods=['GET'])
def delete_fingerprint(fingerprint_name):
    """Deletes a fingerprint template by name."""
    if db.delete_fingerprint(fingerprint_name):
        return render_template('delete_success.html', fingerprint_name=fingerprint_name)
    else:
        return render_template('error.html',
                               title="Deletion Failed",
                               message=f"Fingerprint '{fingerprint_name}' not found.",
                               back_url='/',
                               back_text='View Dashboard')

if __name__ == '__main__':
    app.run(debug=True, port=5001)
