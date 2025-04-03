import requests
import time
import uuid
import hmac
import hashlib
import base64
import logging

logger = logging.getLogger(__name__)

SWITCHBOT_BASE_URL = "https://api.switch-bot.com/v1.1"

class SwitchBotAPI:
    @staticmethod
    def get_headers(user):
        """Get authentication headers for SwitchBot API"""
        cred = getattr(user, 'switchbot_credential', None)
        if not cred:
            logger.warning(f"No SwitchBot credentials found for user {user.id}")
            return None
            
        token = cred.token
        secret = cred.secret
        
        # 空文字列チェック
        if not token or not secret:
            logger.error(f"Empty credentials for user {user.id}")
            return None
            
        try:
            t = str(int(round(time.time() * 1000)))
            nonce = str(uuid.uuid4())
            string_to_sign = token + t + nonce
            signature = hmac.new(
                key=secret.encode('utf-8'),
                msg=string_to_sign.encode('utf-8'),
                digestmod=hashlib.sha256
            ).digest()
            sign = base64.b64encode(signature).decode('utf-8').upper()

            return {
                "Authorization": token,
                "Content-Type": "application/json",
                "t": t,
                "sign": sign,
                "nonce": nonce
            }
        except Exception as e:
            logger.error(f"Error generating SwitchBot headers: {str(e)}")
            return None
    
    @staticmethod
    def get_devices(user):
        """Get all devices from SwitchBot API"""
        headers = SwitchBotAPI.get_headers(user)
        if headers is None:
            return None, "SwitchBot credentials not registered."
            
        try:
            url = f"{SWITCHBOT_BASE_URL}/devices"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.RequestException as e:
            logger.error(f"SwitchBot API error: {str(e)}")
            return None, f"SwitchBot API error: {str(e)}"
    
    @staticmethod
    def get_device_status(user, device_id):
        """Get status of a specific device"""
        headers = SwitchBotAPI.get_headers(user)
        if headers is None:
            return None, "SwitchBot credentials not registered."
            
        try:
            url = f"{SWITCHBOT_BASE_URL}/devices/{device_id}/status"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json().get('body', {}), None
        except requests.exceptions.RequestException as e:
            logger.error(f"SwitchBot API error: {str(e)}")
            return None, f"SwitchBot API error: {str(e)}"
    
    @staticmethod
    def send_command(user, device_id, command, param="default"):
        """Send command to a device"""
        headers = SwitchBotAPI.get_headers(user)
        if headers is None:
            return None, "SwitchBot credentials not registered."
            
        try:
            url = f"{SWITCHBOT_BASE_URL}/devices/{device_id}/commands"
            payload = {
                "command": command,
                "parameter": param,
                "commandType": "command"
            }
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.RequestException as e:
            logger.error(f"SwitchBot API error: {str(e)}")
            return None, f"SwitchBot API error: {str(e)}"