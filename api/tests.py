import json
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model


User = get_user_model()

class AuthTests(APITestCase):
    """
    ユーザー登録 (Register) / ログイン (Login) / ログアウト (Logout) をまとめてテスト。
    メール機能なし (username + password のみ) の場合を想定。
    """

    def test_register_success(self):
        """
        ユーザー名 + パスワードのみで登録が成功
        """
        url = reverse('register')  # /api/register/
        data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("detail", response.data)

    def test_register_duplicate_username(self):
        """
        ユーザー名が重複する場合、400 が返る
        """
        # 先に登録
        User.objects.create_user(username="testuser", password="anypass")
        url = reverse('register')
        data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_success(self):
        """
        ログイン成功時は access / refresh が返る
        """
        # 先にユーザー作成
        user = User.objects.create_user(username="testuser", password="testpass123")

        url = reverse('login')  # /api/login/
        data = {
            "username": "testuser",
            "password": "testpass123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_login_failure_wrong_password(self):
        """
        パスワード誤りで 400
        """
        user = User.objects.create_user(username="testuser", password="testpass123")

        url = reverse('login')
        data = {
            "username": "testuser",
            "password": "wrongpassword"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_success(self):
        """
        有効な refresh でログアウト → 205
        """
        # 1)ユーザー作成
        user = User.objects.create_user(username="logoutuser", password="logoutpass123")
        # 2)ログイン
        login_url = reverse('login')
        login_data = {"username": "logoutuser", "password": "logoutpass123"}
        login_res = self.client.post(login_url, login_data, format="json")
        self.assertEqual(login_res.status_code, status.HTTP_200_OK)
        refresh_token = login_res.data["refresh"]

        # 3)ログアウト
        logout_url = reverse('logout')  # /api/logout/
        response = self.client.post(logout_url, {"refresh": refresh_token}, format="json")
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
        self.assertEqual(response.data["detail"], "Logged out successfully.")

    def test_logout_invalid_token(self):
        """
        無効なリフレッシュトークンでログアウト → 400
        """
        logout_url = reverse('logout')
        response = self.client.post(logout_url, {"refresh": "invalidtoken"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "Invalid token.")

    def test_logout_no_token(self):
        """
        refresh が無い場合 → 400
        """
        logout_url = reverse('logout')
        response = self.client.post(logout_url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "Invalid token.")