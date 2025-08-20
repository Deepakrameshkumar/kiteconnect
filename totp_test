import pyotp
import time
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Get the TOTP secret from the environment
totp_secret = os.getenv("TOTP_SECRET")

if not totp_secret:
    raise ValueError("TOTP_SECRET not found in .env file")

totp = pyotp.TOTP(totp_secret)
print("Current TOTP code:", totp.now())
time.sleep(30)
print("Next TOTP code:", totp.now())
