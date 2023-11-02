import pyotp
import qrcode
import time
from io import BytesIO
from base64 import b64encode
import requests

def generate_secret():
    return pyotp.random_base32()

def generate_qr_code(secret, username):
    totp = pyotp.TOTP(secret)
    # Constructing a provision URI to display in QR code format
    provision_uri = totp.provisioning_uri(name=username, issuer_name="HelenesRosaBlogg")
    # Using the qrcode library to produce a QR code to display
    img = qrcode.make(provision_uri)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    img_str = b64encode(buffer.getvalue()).decode('utf-8')
    return img_str


def verify_totp(token, secret):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)


#henter ut email

def get_user_email(access_token):
    url = "https://people.googleapis.com/v1/people/me?personFields=emailAddresses"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        user_info = response.json()
        email = user_info.get("emailAddresses", [{}])[0].get("value")
        return email
    else:
        print(f"Error fetching user info: {response.status_code}")
        return None
