import logging
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from .serializers import (
    RegisterSerializer, LoginSerializer, SwitchBotTokenSerializer
)
from .models import SwitchBotCredential
from .utils import SwitchBotAPI
from .rate_limiter import RateLimiter

User = get_user_model()
logger = logging.getLogger(__name__)

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(
                {"detail": "Registration successful."},
                status=status.HTTP_201_CREATED
            )
        logger.warning(f"Registration failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
        logger.warning(f"Login failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
                
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logged out successfully."}, status=status.HTTP_205_RESET_CONTENT)
        except TokenError as e:
            logger.warning(f"Invalid token error during logout: {str(e)}")
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error during logout: {str(e)}")
            return Response({"detail": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
        logger.warning(f"Token update failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DeviceListView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        data, error = SwitchBotAPI.get_devices(request.user)
        if error:
            return Response({"detail": error}, status=status.HTTP_400_BAD_REQUEST)
            
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

class DeviceStatusView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, deviceId):
        status_data, error = SwitchBotAPI.get_device_status(request.user, deviceId)
        if error:
            return Response({"detail": error}, status=status.HTTP_400_BAD_REQUEST)
        return Response(status_data)

class DeviceCommandView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, deviceID, command):
        param_value = request.data.get("param", "default")
        result, error = SwitchBotAPI.send_command(request.user, deviceID, command, param_value)
        
        if error:
            return Response({"detail": error}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result)

class DeviceStatusView(APIView):
    permission_classes = [IsAuthenticated]
    
    @RateLimiter.limit_api_calls
    def get(self, request, deviceId):
        status_data, error = SwitchBotAPI.get_device_status(request.user, deviceId)
        if error:
            return Response({"detail": error}, status=status.HTTP_400_BAD_REQUEST)
        return Response(status_data)

class DeviceCommandView(APIView):
    permission_classes = [IsAuthenticated]
    
    @RateLimiter.limit_api_calls
    def post(self, request, deviceID, command):
        param_value = request.data.get("param", "default")
        result, error = SwitchBotAPI.send_command(request.user, deviceID, command, param_value)
        
        if error:
            return Response({"detail": error}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result)