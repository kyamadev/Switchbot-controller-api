from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import SwitchBotCredential

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password')
    
    def create(self, validated_data):
        # ユーザー作成時は初期状態で inactive とする
        user = User.objects.create_user(**validated_data)
        user.is_active = False
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username_or_email = data.get("username_or_email")
        password = data.get("password")
        user = None
        # ユーザー名またはメールアドレスで認証
        try:
            user = User.objects.get(username=username_or_email)
        except User.DoesNotExist:
            try:
                user = User.objects.get(email=username_or_email)
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid login credentials.")
        if not user.check_password(password):
            raise serializers.ValidationError("Invalid login credentials.")
        if not user.is_active:
            raise serializers.ValidationError("User account is not active.")
        data["user"] = user
        return data

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class SwitchBotTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = SwitchBotCredential
        fields = ('token', 'secret')