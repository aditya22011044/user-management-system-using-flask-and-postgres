import random
import string
from flask_mail import Message
from email_validator import validate_email, EmailNotValidError


def generate_otp():
    otp = ''.join(random.choices(string.digits, k=6))
    return otp


def send_otp_email(mail, recipient_email, otp):
    try:
        validate_email(recipient_email)

        msg = Message("Your OTP Code", recipients=[recipient_email])
        msg.body = f"Your OTP code is: {otp}"
        mail.send(msg)
        return True

    except EmailNotValidError as e:
        print(f"Invalid email: {e}")
        return False

    except Exception as e:
        print(f"Error sending email: {e}")
        return False
