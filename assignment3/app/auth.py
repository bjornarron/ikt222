import pyotp
import qrcode
import time
from io import BytesIO
from base64 import b64encode

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
