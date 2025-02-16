import requests
import time
import uuid
import hmac
import hashlib
import base64
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    RegisterSerializer, LoginSerializer, ResetPasswordSerializer, SwitchBotTokenSerializer
)
from .models import SwitchBotCredential

User = get_user_model()
SWITCHBOT_BASE_URL = "https://api.switch-bot.com/v1.1"


# メール送信用ユーティリティ（アクティベーション／パスワードリセット用）
def send_activation_email(user, request):
    signer = TimestampSigner()
    token = signer.sign(user.pk)
    activation_url = f"{settings.FRONTEND_URL}/register/activate/{token}"
    subject = "Activate your account"
    message = f"Click the link to activate your account: {activation_url}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])


class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            send_activation_email(user, request)
            return Response(
                {"detail": "Registration successful. Check your email for activation link."},
                status=status.HTTP_201_CREATED
            )
        # エラー出力用
        # TODO: エラー内容をフロントに出力
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# アクティベーション用ビュー
class ActivateAccountView(APIView):
    def get(self, request, token):
        signer = TimestampSigner()
        try:
            # 1日以内の有効期限（必要に応じて調整）
            unsigned_value = signer.unsign(token, max_age=60*60*24)
            user_id = unsigned_value
            user = User.objects.get(pk=user_id)
            user.is_active = True
            user.save()
            return Response({"detail": "Account activated successfully."}, status=status.HTTP_200_OK)
        except SignatureExpired:
            return Response({"detail": "Activation link expired."}, status=status.HTTP_400_BAD_REQUEST)
        except (BadSignature, User.DoesNotExist):
            return Response({"detail": "Invalid activation link."}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        try:
            # フロントエンドからrefreshトークンを受け取り、ブラックリスト化
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logged out successfully."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                signer = TimestampSigner()
                token = signer.sign(user.pk)
                reset_url = f"{settings.FRONTEND_URL}/resetpassword_confirm/{token}"
                subject = "Reset your password"
                message = f"Click the link to reset your password: {reset_url}"
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
                return Response({"detail": "Password reset email sent."})
            except User.DoesNotExist:
                return Response({"detail": "Email not found."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordConfirmView(APIView):
    def get(self, request, token):
        signer = TimestampSigner()
        try:
            # トークン有効期限: 1日 (60*60*24)
            unsigned_value = signer.unsign(token, max_age=60*60*24)
            user_id = unsigned_value
            # ユーザーが存在し、有効なトークン
            # フロントエンド向けに "OK" 的なレスポンスを返す
            return Response({"detail": "Token is valid. You can reset your password now."}, status=status.HTTP_200_OK)
        except SignatureExpired:
            return Response({"detail": "Reset link expired."}, status=status.HTTP_400_BAD_REQUEST)
        except (BadSignature, User.DoesNotExist):
            return Response({"detail": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, token):
        signer = TimestampSigner()
        try:
            unsigned_value = signer.unsign(token, max_age=60*60*24)
            user_id = unsigned_value
            user = User.objects.get(pk=user_id)
        except SignatureExpired:
            return Response({"detail": "Reset link expired."}, status=status.HTTP_400_BAD_REQUEST)
        except (BadSignature, User.DoesNotExist):
            return Response({"detail": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)

        new_password = request.data.get("password")
        if not new_password:
            return Response({"detail": "No password provided."}, status=status.HTTP_400_BAD_REQUEST)

        # パスワードの再設定
        user.set_password(new_password)
        user.save()

        return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)

# token/secretを登録／上書きするエンドポイント
class SwitchBotTokenView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request):
        serializer = SwitchBotTokenSerializer(data=request.data)
        if serializer.is_valid():
            obj, created = SwitchBotCredential.objects.update_or_create(
                user=request.user,
                defaults=serializer.validated_data
            )
            return Response({"detail": "SwitchBot token updated."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ユーザーに紐づいた SwitchBot 認証情報から、デバイス一覧を取得
def get_switchbot_headers(user):
    cred = getattr(user, 'switchbot_credential', None)
    if not cred:
        return None
    token = cred.token
    secret = cred.secret
    t = str(int(round(time.time() * 1000)))  # ミリ秒単位の現在時刻
    nonce = str(uuid.uuid4())
    string_to_sign = token + t + nonce
    signature = hmac.new(
        key=secret.encode('utf-8'),
        msg=string_to_sign.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    sign = base64.b64encode(signature).decode('utf-8').upper()

    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "t": t,
        "sign": sign,
        "nonce": nonce
    }
    return headers


class DeviceListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        headers = get_switchbot_headers(request.user)
        if headers is None:
            return Response(
                {"detail": "SwitchBot credentials not registered."},
                status=status.HTTP_400_BAD_REQUEST
            )
        url = f"{SWITCHBOT_BASE_URL}/devices"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            devices = []
            body = data.get('body', {})
            for d in body.get('deviceList', []):
                devices.append({
                    "deviceId": d.get("deviceId"),
                    "deviceName": d.get("deviceName"),
                    "deviceType": d.get("deviceType")
                })
            for d in body.get('infraredRemoteList', []):
                devices.append({
                    "deviceId": d.get("deviceId"),
                    "deviceName": d.get("deviceName"),
                    "deviceType": d.get("deviceType"),
                    "remoteType": d.get("remoteType"),
                })
            return Response({"devices": devices})
        else:
            return Response(
                {"detail": "Failed to fetch devices."},
                status=r.status_code
            )


class DeviceStatusView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, deviceId):
        headers = get_switchbot_headers(request.user)
        if headers is None:
            return Response(
                {"detail": "SwitchBot credentials not registered."},
                status=status.HTTP_400_BAD_REQUEST
            )
        url = f"{SWITCHBOT_BASE_URL}/devices/{deviceId}/status"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            return Response(data.get('body', {}))
        else:
            return Response(
                {"detail": "Failed to fetch device status."},
                status=r.status_code
            )


class DeviceCommandView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, deviceID, command):
        headers = get_switchbot_headers(request.user)
        if headers is None:
            return Response(
                {"detail": "SwitchBot credentials not registered."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        param_value = request.data.get("param", "default")
        url = f"{SWITCHBOT_BASE_URL}/devices/{deviceID}/commands"
        payload = {
            "command": command,
            "parameter": param_value,
            "commandType": "command"
        }
        r = requests.post(url, json=payload, headers=headers)
        if r.status_code == 200:
            data = r.json()
            return Response(data)
        else:
            return Response(
                {"detail": "Failed to send command."},
                status=r.status_code
            )