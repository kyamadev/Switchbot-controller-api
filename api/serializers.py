from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import SwitchBotCredential

User = get_user_model()

class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists.")
        return value

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            is_active=True,
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")
        user = None
        # ユーザー名で認証
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid login credentials.")
        if not user.check_password(password):
            raise serializers.ValidationError("Invalid login credentials.")
        data["user"] = user
        return data

class SwitchBotTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = SwitchBotCredential
        fields = ('token', 'secret')