from flask import Flask, request, jsonify
import requests
import pyotp
import hashlib

app = Flask(__name__)

@app.route('/get_access_token', methods=['POST'])
def get_access_token():
    try:
        # Get JSON payload from request
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON payload provided"}), 400

        # Extract required fields
        api_key = data.get("api_key")
        api_secret = data.get("api_secret")
        login_id = data.get("login_id")
        login_password = data.get("login_password")
        totp_secret = data.get("totp_secret")

        # Validate inputs
        if not all([api_key, api_secret, login_id, login_password, totp_secret]):
            return jsonify({"error": "Missing required fields"}), 400

        # Step 1: Generate TOTP
        totp = pyotp.TOTP(totp_secret)
        twofa_value = totp.now()
        print("Generated TOTP:", twofa_value)  # Debugging

        # Step 2: Login (Step 1 - Submit user_id and password)
        login_url = "https://kite.zerodha.com/api/login"
        login_payload = {
            "user_id": login_id,
            "password": login_password
        }
        headers = {
            "X-Kite-Version": "3",
            "User-Agent": "KiteConnect/3.0"
        }

        login_response = requests.post(login_url, data=login_payload, headers=headers)
        login_response.raise_for_status()
        login_data = login_response.json()
        print("Login Response:", login_data)  # Debugging
        if login_data.get("status") != "success":
            return jsonify({"error": f"Login failed: {login_data.get('message')}"}), 400
        request_id = login_data["data"]["request_id"]

        # Step 3: Two-Factor Authentication (TFA)
        tfa_url = "https://kite.zerodha.com/api/twofa"
        tfa_payload = {
            "user_id": login_id,
            "request_id": request_id,
            "twofa_value": twofa_value
        }

        tfa_response = requests.post(tfa_url, data=tfa_payload, headers=headers)
        tfa_response.raise_for_status()
        tfa_data = tfa_response.json()
        print("TFA Response:", tfa_data)  # Debugging
        if tfa_data.get("status") != "success":
            return jsonify({"error": f"TFA failed: {tfa_data.get('message')}"}), 400
        if "data" not in tfa_data or "request_token" not in tfa_data["data"]:
            return jsonify({"error": "TFA response missing request_token"}), 400
        request_token = tfa_data["data"]["request_token"]

        # Step 4: Generate access_token
        checksum = hashlib.sha256((api_key + request_token + api_secret).encode()).hexdigest()
        session_url = "https://api.kite.trade/session/token"
        session_payload = {
            "api_key": api_key,
            "request_token": request_token,
            "checksum": checksum
        }

        session_response = requests.post(session_url, data=session_payload, headers=headers)
        session_response.raise_for_status()
        session_data = session_response.json()
        if session_data.get("status") != "success":
            return jsonify({"error": f"Session generation failed: {session_data.get('message')}"}), 400
        access_token = session_data["data"]["access_token"]

        return jsonify({"access_token": access_token}), 200

    except requests.RequestException as e:
        return jsonify({"error": f"HTTP request failed: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)