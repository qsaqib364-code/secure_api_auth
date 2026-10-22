import aiosmtplib
from email.message import EmailMessage
from app.config import settings
from datetime import datetime
from zoneinfo import ZoneInfo

async def send_otp_email(to_email: str, otp_code: str):
    message = EmailMessage()
    message["From"] = "Security Team <security@yourapp.com>"
    message["To"] = to_email
    message["Subject"] = "Your Secure Auth OTP Code"
    
    html_content = f"""
    <h2>Security Verification</h2>
    <p>Aapke account mein naye device se login karne ki koshish ki gayi hai.</p>
    <p>Aapka One-Time Password (OTP) yeh hai:</p>
    <h1 style="color: blue; font-size: 32px; letter-spacing: 5px;">{otp_code}</h1>
    <p>Yeh code <b>5 minute</b> ke liye valid hai. Kisi ke sath share na karein.</p>
    """
    message.set_content(html_content, subtype="html")
    try:
        await aiosmtplib.send(
            message, hostname=settings.SMTP_HOST, port=settings.SMTP_PORT,
            username=settings.SMTP_USER, password=settings.SMTP_PASSWORD,
            use_tls=False, start_tls=True 
        )
        print(f"✅ OTP Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

async def send_password_reset_email(to_email: str, reset_token: str):
    message = EmailMessage()
    message["From"] = "Security Team <security@yourapp.com>"
    message["To"] = to_email
    message["Subject"] = "Password Reset Request"
    
    html_content = f"""
    <h2>Password Reset</h2>
    <p>Humne aapke account ke liye password reset request receive ki hai.</p>
    <p>Naya password set karne ke liye yeh token use karein:</p>
    <h3 style="color: red; background: #f4f4f4; padding: 10px;">{reset_token}</h3>
    <p>Yeh token <b>15 minute</b> ke liye valid hai. Agar aapne yeh request nahi ki, to is email ko ignore karein.</p>
    """
    message.set_content(html_content, subtype="html")
    try:
        await aiosmtplib.send(
            message, hostname=settings.SMTP_HOST, port=settings.SMTP_PORT,
            username=settings.SMTP_USER, password=settings.SMTP_PASSWORD,
            use_tls=False, start_tls=True 
        )
        print(f"✅ Reset Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

async def send_security_alert_email(to_email: str, event_type: str, ip_address: str, user_agent: str):
    message = EmailMessage()
    message["From"] = "Security Team <security@yourapp.com>"
    message["To"] = to_email
    message["Subject"] = f"Security Alert: {event_type} Detected"
    
    pkt_time = datetime.now(ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %I:%M %p")
    
    html_content = f"""
    <div style="font-family: Arial; border: 1px solid #ccc; padding: 20px; border-radius: 8px;">
        <h2 style="color: red;">Security Alert!</h2>
        <p>Aapke account par ek suspicious activity detect hui hai.</p>
        <ul>
            <li><b>Event:</b> {event_type}</li>
            <li><b>Time (PKT):</b> {pkt_time}</li>
            <li><b>IP Address:</b> {ip_address}</li>
            <li><b>Device/Browser:</b> {user_agent[:50]}...</li>
        </ul>
        <p>Agar ye aap nahi the, to foran apna password change karein aur saare devices se logout karein.</p>
    </div>
    """
    message.set_content(html_content, subtype="html")
    try:
        await aiosmtplib.send(
            message, hostname=settings.SMTP_HOST, port=settings.SMTP_PORT,
            username=settings.SMTP_USER, password=settings.SMTP_PASSWORD,
            use_tls=False, start_tls=True 
        )
        print(f"✅ Security Alert sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")