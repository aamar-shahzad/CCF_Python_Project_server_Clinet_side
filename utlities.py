import requests
import json
import os
import subprocess
import sys
import base64
import hashlib
from urllib.parse import urlparse
import subprocess
import json
import time
import os
import glob


RSA_SIZE = 2048


DEFAULT_CURVE = "secp384r1"
FAST_CURVE = "secp256r1"
SUPPORTED_CURVES = [DEFAULT_CURVE, FAST_CURVE]

DIGEST_SHA384 = "sha384"
DIGEST_SHA256 = "sha256"

RSA_SIZE = 2048
# CCF network node
server="https://127.0.0.1:8000"

num_users = 10



#  delting file if available for user 
def delete_user_files(num_users):
    for i in range(num_users):
        # File names based on user index
        cert_file = f"user{i}_cert.pem"
        priv_key_file = f"user{i}_privk.pem"
        enc_priv_file = f"user{i}_enc_privk.pem"
        enc_pub_file = f"user{i}_enc_pubk.pem"

        # Delete the files if they exist
        for file in [cert_file, priv_key_file, enc_priv_file, enc_pub_file]:
            if os.path.exists(file):
                os.remove(file)
                print(f"Deleted {file}")
            else:
                print(f"{file} does not exist")

        # Delete all JSON files related to the user
        for json_file in glob.glob(f"set_user{i}*.json"):
            os.remove(json_file)
            print(f"Deleted {json_file}")

# Specify the number of users to delete

delete_user_files(num_users)



# Getting Network metrices
url = server + "/app/api/metrics"

try:
    response = requests.get(url, verify='service_cert.pem')

    print("Status Code:", response.status_code)
    print("\nResponse Headers:")
    for header, value in response.headers.items():
        print(f"{header}: {value}")

    print("\nResponse Body:")
    try:
        # Attempt to parse JSON and print it in an indented format
        response_json = response.json()
        print(json.dumps(response_json, indent=4))
    except ValueError:
        # If response is not JSON, print as plain text
        print(response.text)

except requests.exceptions.RequestException as e:
    print("Error making request:", e)

# Keygenrator function for public and private key with ballat request file


def generate_keys(name, curve=DEFAULT_CURVE, generate_encryption_key=False):
    if not name:
        print("Error: The name of the participant should be specified (e.g. member0 or user1)")
        sys.exit(1)

    if curve not in SUPPORTED_CURVES:
        print(f"{curve} curve is not in {SUPPORTED_CURVES}")
        sys.exit(1)

    digest = DIGEST_SHA384 if curve == DEFAULT_CURVE else DIGEST_SHA256

    cert = f"{name}_cert.pem"
    privk = f"{name}_privk.pem"

    print(f"-- Generating identity private key and certificate for participant \"{name}\"...")
    print(f"Identity curve: {curve}")

    subprocess.run(["openssl", "ecparam", "-out", privk, "-name", curve, "-genkey"], check=True)
    subprocess.run(["openssl", "req", "-new", "-key", privk, "-x509", "-nodes", "-days", "365", "-out", cert, f"-{digest}", "-subj", f"/CN={name}"], check=True)

    print(f"Identity private key generated at: {privk}")
    print(f"Identity certificate generated at: {cert} (to be registered in CCF)")

    if generate_encryption_key:
        print(f"-- Generating RSA encryption key pair for participant \"{name}\"...")

        enc_priv = f"{name}_enc_privk.pem"
        enc_pub = f"{name}_enc_pubk.pem"

        subprocess.run(["openssl", "genrsa", "-out", enc_priv, str(RSA_SIZE)], check=True)
        subprocess.run(["openssl", "rsa", "-in", enc_priv, "-pubout", "-out", enc_pub], check=True)

        print(f"Encryption private key generated at: {enc_priv}")
        print(f"Encryption public key generated at: {enc_pub} (to be registered in CCF)")



# CA certificate creator function
def create_certificate(cert_name):
    cert_file = f"{cert_name}_cert.pem"
    set_user_file = f"set_{cert_name}.json"
    
    # Call the generate_keys function (make sure to include it in your script)
    generate_keys(cert_name)

    # Read the certificate file and format it
    with open(cert_file, 'r') as file:
        cert_content = file.read().replace('\n', '\n')

    # Create the JSON content
    user_json = {
        "actions": [
            {
                "name": "set_user",
                "args": {
                    "cert": cert_content
                }
            }
        ]
    }

    # Write the JSON to a file
    with open(set_user_file, 'w') as file:
        json.dump(user_json, file, indent=2)
    print(f"JSON file created at: {set_user_file}")
    




def send_secure_request(url, request_data_path, signing_privk, signing_cert, command="post"):
    def read_request_data(request_path):
        if request_path.startswith('@'):
            with open(request_path[1:], 'r') as file:
                return file.read()
        else:
            return request_path

    def calculate_digest(data):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data.encode('utf-8'))
        return base64.b64encode(sha256_hash.digest()).decode()

    def create_signature(string_to_sign, priv_key_path):
        process = subprocess.Popen(
            ['openssl', 'dgst', '-sha384', '-sign', priv_key_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        signature, _ = process.communicate(string_to_sign.encode())
        return base64.b64encode(signature).decode().replace('\n', '')

    def prepare_string_to_sign(method, url, digest, data_length):
        parsed_url = urlparse(url)
        path = parsed_url.path
        return f"(request-target): {method.lower()} {path}\ndigest: SHA-256={digest}\ncontent-length: {data_length}"

    def get_cert_key_id(cert_path):
        proc = subprocess.Popen(
            ['openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output, _ = proc.communicate()
        fingerprint = output.decode().split('=')[1].replace(':', '').lower().replace('\n', '')
        return fingerprint

    request_data = read_request_data(request_data_path)
    request_digest = calculate_digest(request_data)
    string_to_sign = prepare_string_to_sign(command, url, request_digest, str(len(request_data)))
    signature = create_signature(string_to_sign, signing_privk)
    key_id = get_cert_key_id(signing_cert)

    headers = {
        "Digest": f"SHA-256={request_digest}",
        "Authorization": f'Signature keyId="{key_id}",algorithm="hs2019",headers="(request-target) digest content-length",signature="{signature}"'
    }

    response = requests.post(url, data=request_data, headers=headers, verify='service_cert.pem')
    return response.status_code, response.text




# sending voting to add  the user based on proposal id 

def send_ballot_request(server_url, proposal_id, data_file_path, signing_privk_path, signing_cert_path):
    def read_request_data(file_path):
        with open(file_path, 'r') as file:
            return file.read()

    def calculate_digest(data):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data.encode('utf-8'))
        return base64.b64encode(sha256_hash.digest()).decode()

    def create_signature(string_to_sign, priv_key_path):
        process = subprocess.Popen(
            ['openssl', 'dgst', '-sha384', '-sign', priv_key_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        signature, _ = process.communicate(string_to_sign.encode())
        return base64.b64encode(signature).decode().replace('\n', '')

    def prepare_string_to_sign(url, digest, data_length):
        parsed_url = urlparse(url)
        path = parsed_url.path
        return f"(request-target): post {path}\ndigest: SHA-256={digest}\ncontent-length: {data_length}"

    def get_cert_key_id(cert_path):
        proc = subprocess.Popen(
            ['openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output, _ = proc.communicate()
        fingerprint = output.decode().split('=')[1].replace(':', '').lower().replace('\n', '')
        return fingerprint

    url = f"{server_url}/gov/proposals/{proposal_id}/ballots"
    request_data = read_request_data(data_file_path)
    request_digest = calculate_digest(request_data)
    string_to_sign = prepare_string_to_sign(url, request_digest, str(len(request_data)))
    signature = create_signature(string_to_sign, signing_privk_path)
    key_id = get_cert_key_id(signing_cert_path)

    headers = {
        "Digest": f"SHA-256={request_digest}",
        "Authorization": f'Signature keyId="{key_id}",algorithm="hs2019",headers="(request-target) digest content-length",signature="{signature}"',
        "Content-Type": "application/json"
    }

    response = requests.post(url, data=request_data, headers=headers, verify='service_cert.pem')
    return response.status_code, response.json()





# creation of user id based on certifacte 
def get_certificate_fingerprint(cert_path):
    process = subprocess.Popen(
        ['openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    output, _ = process.communicate()
    fingerprint = output.decode().split('=')[1].replace(':', '').lower().strip()
    return fingerprint


def main_process(num_initial_users):
    # Generate keys and certificates for all users
    for i in range(num_initial_users):
        create_certificate(f"user{i}")

    # Submit proposal and voting for each user
    for i in range(num_initial_users):
        user_name = f"user{i}"
        user_cert_path = f"{user_name}_cert.pem"
        user_key_path = f"{user_name}_privk.pem"

        # Member0 submits the proposal
        status_code, response_json = send_secure_request(server + "/gov/proposals", f"@set_{user_name}.json", "member0_privk.pem", "member0_cert.pem", "post")
        print("proposal_id",json.loads(response_json)['proposal_id'])
        proposal_id=json.loads(response_json)['proposal_id']

        # Other members vote
        for j in range(1, 3):  # Assuming 2 other members (member1 and member2)
            vote_status, response_json = send_ballot_request(server, proposal_id, "vote_accept.json", f"member{j}_privk.pem", f"member{j}_cert.pem")
            # print("vote_status",vote_status,"response_json",response_json)
            if vote_status != 200:
                print(f"Voting failed for {user_name} by member{j}")
                continue
            time.sleep(1)  # Delay for processing

        # Create account for the user
        user_id=get_certificate_fingerprint(user_cert_path)
        print("Actual id",user_id) 
   
      
       


# Run the script for a specified number of users
main_process(num_users)