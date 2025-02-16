import json
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from django.core import signing

User = get_user_model()

class RegisterTests(APITestCase):
    def test_register_success(self):
        url = reverse('register')
        data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpassword123"
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("detail", response.data)

class ActivateAccountTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser", email="test@example.com", password="password")
        self.user.is_active = False
        self.user.save()
        self.signer = signing.TimestampSigner()

    def test_activate_success(self):
        token = self.signer.sign(self.user.pk)
        url = reverse('activate', args=[token])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("detail"), "Account activated successfully.")

    def test_activate_invalid_token(self):
        url = reverse('activate', args=["invalidtoken"])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class LoginTests(APITestCase):
    def setUp(self):
        self.password = "password123"
        self.user = User.objects.create_user(username="testuser", email="test@example.com", password=self.password)
        self.user.is_active = True
        self.user.save()

    def test_login_success(self):
        url = reverse('login')
        data = {"username_or_email": "testuser", "password": self.password}
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_login_failure(self):
        url = reverse('login')
        data = {"username_or_email": "testuser", "password": "wrongpassword"}
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
