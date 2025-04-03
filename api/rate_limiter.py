import time
import logging
from django.core.cache import cache
from functools import wraps
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    Rate limiter for SwitchBot API to prevent exceeding their rate limits.
    SwitchBot API limits are 1000 calls per day per token, with a maximum
    of 10 calls per 15 seconds for the same device.
    """
    
    @staticmethod
    def limit_api_calls(view_func):
        """
        Decorator to limit API calls to SwitchBot.
        - Limits per user (using user id as key)
        - Limits per device (using device id as key)
        """
        @wraps(view_func)
        def wrapped_view(self, request, *args, **kwargs):
            user_id = request.user.id
            device_id = kwargs.get('deviceId') or kwargs.get('deviceID')
            
            # Daily limit per user (1000 calls per day)
            user_daily_key = f"switchbot_daily_limit_{user_id}"
            user_daily_count = cache.get(user_daily_key, 0)
            
            if user_daily_count >= 1000:
                logger.warning(f"User {user_id} exceeded daily SwitchBot API limit")
                return Response(
                    {"detail": "1日のAPI呼び出し制限に達しました。明日再試行してください。"},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            
            # Short-term limit per device (10 calls per 15 seconds)
            if device_id:
                device_key = f"switchbot_device_limit_{device_id}"
                device_count = cache.get(device_key, 0)
                
                if device_count >= 10:
                    logger.warning(f"Rate limit exceeded for device {device_id}")
                    return Response(
                        {"detail": "デバイスへのリクエストが多すぎます。少し待ってから再試行してください。"},
                        status=status.HTTP_429_TOO_MANY_REQUESTS
                    )
                
                # Increment device counter
                cache.set(device_key, device_count + 1, timeout=15)  # 15 seconds
            
            # Increment user daily counter
            cache.set(user_daily_key, user_daily_count + 1, timeout=86400)  # 24 hours
            
            # Call the original view function
            return view_func(self, request, *args, **kwargs)
        
        return wrapped_view