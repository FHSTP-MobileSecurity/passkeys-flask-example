from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
import json
from webauthn import ( 
    generate_registration_options,
    generate_authentication_options,
    verify_registration_response,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes
)
from webauthn.helpers.structs import (
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor
)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///webauthn.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


RP_ID = 'localhost'
RP_NAME = 'FHSTP RP'
USER_ID = 'user123'

class Registration(db.Model):
    id = db.Column(db.String, primary_key=True)
    credential_id = db.Column(db.LargeBinary, nullable=False)
    credential_public_key = db.Column(db.String, nullable=False)
    sign_count = db.Column(db.Integer, nullable=False)

class Challenge(db.Model):
    id = db.Column(db.String, primary_key=True)
    challenge = db.Column(db.String, nullable=False)

@app.before_request
def create_tables():
    db.create_all()


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


# generates registration options
@app.route('/register', methods=['GET'])
def register():
    registration_options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=USER_ID
    )
    options_json = options_to_json(registration_options)

    # Check if challenge already exists
    challenge = Challenge.query.get(USER_ID)
    if challenge:
        # Remove old challenge
        db.session.delete(challenge)
    
    # Store challenge in the database
    try:
        challenge = Challenge(id=USER_ID, challenge=json.loads(options_json)['challenge'])
        db.session.add(challenge)
        db.session.commit()
    except Exception as e:
            return jsonify({"status": "failed", "error": str(e)}), 400
    
    return jsonify(options_json)


# verifies the registration response
@app.route('/register', methods=['POST'])
def verify_registration():
    response = request.json
    try:
        # Retrieve challenge from the database
        challenge = Challenge.query.get(USER_ID)
        if not challenge:
            return jsonify({"status": "failed", "error": "Challenge not found"}), 400
        
        verified_registration = verify_registration_response(
            credential=response,
            expected_challenge=base64url_to_bytes(challenge.challenge),
            expected_rp_id=RP_ID,
            expected_origin=f'http://{RP_ID}:8000',
            require_user_verification=True
        )

        # store registration in database
        registration = Registration(
            id=USER_ID,
            credential_id=verified_registration.credential_id,
            credential_public_key=verified_registration.credential_public_key,
            sign_count=verified_registration.sign_count
        )
        db.session.add(registration)
        db.session.commit()

        # Remove challenge from the database after successful registration
        db.session.delete(challenge)
        db.session.commit()

        return jsonify({"status": "ok"})
    except Exception as e:
        print(e)
        return jsonify({"status": "failed", "error": str(e)}), 400


# generates authentication options
@app.route('/authenticate', methods=['GET'])
def authenticate():
    registration = Registration.query.get(USER_ID)
    if not registration:
        return jsonify({"status": "failed", "error": "Credential ID not recognized"}), 401
    authentication_options = generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.PREFERRED,
        allow_credentials=[PublicKeyCredentialDescriptor(id=registration.credential_id)]
    )
    print(authentication_options)
    options_json = options_to_json(authentication_options)

    # Check if challenge already exists
    challenge = Challenge.query.get(USER_ID)
    if challenge:
        # Remove old challenge
        db.session.delete(challenge)

    # store challenge in the database
    challenge = Challenge(id=USER_ID, challenge=json.loads(options_json)['challenge'])
    db.session.add(challenge)
    db.session.commit()

    return jsonify(options_json)


# verify the authentication response
@app.route('/authenticate', methods=['POST'])
def verify_authentication():
    response = request.json
    print(response)
    try:
        # retrieve challenge
        challenge = Challenge.query.get(USER_ID)
        if not challenge:
            return jsonify({"status": "failed", "error": "Challenge not found"}), 400

        # retrieve registrations 
        registration = Registration.query.get(USER_ID)
        if not registration:
            return jsonify({"status": "failed", "error": "Credential ID not recognized"}), 400
        
        verified_authentication = verify_authentication_response(
            credential=response,
            expected_challenge=base64url_to_bytes(challenge.challenge),
            expected_rp_id=RP_ID,
            expected_origin=f'http://{RP_ID}:8000',
            require_user_verification=False,
            credential_public_key=registration.credential_public_key,
            credential_current_sign_count=registration.sign_count
        )
        registration.sign_count = verified_authentication.new_sign_count

        # Remove challenge from the database after successful authentication
        db.session.delete(challenge)
        db.session.commit()

        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "failed", "error": str(e)}), 400


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=8000, debug=True)
