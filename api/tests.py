from unittest.mock import patch
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from django.contrib.auth import get_user_model
from api.models import SwitchBotCredential

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
        self.assertEqual(response.data["detail"], "Refresh token is required.")


class SwitchBotTokenTests(APITestCase):
    """
    SwitchBotのトークン登録・更新のテスト
    """
    
    def setUp(self):
        # テスト用ユーザーを作成
        self.username = "switchbotuser"
        self.password = "switchbotpass"
        self.user = User.objects.create_user(username=self.username, password=self.password)
        
        # ログイン
        self.client = APIClient()
        url = reverse('login')
        data = {"username": self.username, "password": self.password}
        response = self.client.post(url, data, format="json")
        self.access_token = response.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        
    def test_update_switchbot_token_success(self):
        """
        トークンの登録・更新が成功することを確認
        """
        url = reverse('switchbot-token')
        data = {
            "token": "test-token-123",
            "secret": "test-secret-456"
        }
        response = self.client.put(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "SwitchBot token updated.")
        
        # データベースに保存されたことを確認
        credential = SwitchBotCredential.objects.get(user=self.user)
        self.assertEqual(credential.token, "test-token-123")
        self.assertEqual(credential.secret, "test-secret-456")
        
    def test_update_switchbot_token_missing_fields(self):
        """
        必須フィールドが欠けている場合にエラーが返ることを確認
        """
        url = reverse('switchbot-token')
        # tokenフィールドが欠けているデータ
        data = {
            "secret": "test-secret-456"
        }
        response = self.client.put(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_update_switchbot_token_unauthorized(self):
        """
        認証されていないリクエストが拒否されることを確認
        """
        # 認証情報をクリア
        self.client.credentials()
        
        url = reverse('switchbot-token')
        data = {
            "token": "test-token-123",
            "secret": "test-secret-456"
        }
        response = self.client.put(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class DeviceListTests(APITestCase):
    """
    SwitchBotのデバイス一覧取得のテスト
    """
    
    def setUp(self):
        # テスト用ユーザーを作成
        self.username = "devicelistuser"
        self.password = "devicelistpass"
        self.user = User.objects.create_user(username=self.username, password=self.password)
        
        # SwitchBot資格情報を追加
        self.credential = SwitchBotCredential.objects.create(
            user=self.user,
            token="test-token-123",
            secret="test-secret-456"
        )
        
        # ログイン
        self.client = APIClient()
        url = reverse('login')
        data = {"username": self.username, "password": self.password}
        response = self.client.post(url, data, format="json")
        self.access_token = response.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
    
    @patch('api.utils.SwitchBotAPI.get_devices')
    def test_get_device_list_success(self, mock_get_devices):
        """
        デバイス一覧の取得が成功することを確認
        """
        # APIレスポンスをモック
        mock_response = {
            "body": {
                "deviceList": [
                    {
                        "deviceId": "device1",
                        "deviceName": "Test Device 1",
                        "deviceType": "Bot"
                    }
                ],
                "infraredRemoteList": [
                    {
                        "deviceId": "ir1",
                        "deviceName": "Test IR 1",
                        "deviceType": "IR",
                        "remoteType": "TV"
                    }
                ]
            }
        }
        mock_get_devices.return_value = (mock_response, None)
        
        url = reverse('device-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("devices", response.data)
        self.assertEqual(len(response.data["devices"]), 2)
        
        # デバイスの内容確認
        devices = response.data["devices"]
        self.assertEqual(devices[0]["deviceId"], "device1")
        self.assertEqual(devices[0]["deviceName"], "Test Device 1")
        self.assertEqual(devices[0]["deviceType"], "Bot")
        
        self.assertEqual(devices[1]["deviceId"], "ir1")
        self.assertEqual(devices[1]["deviceName"], "Test IR 1")
        self.assertEqual(devices[1]["deviceType"], "IR")
        self.assertEqual(devices[1]["remoteType"], "TV")
    
    @patch('api.utils.SwitchBotAPI.get_devices')
    def test_get_device_list_error(self, mock_get_devices):
        """
        APIからエラーが返された場合のハンドリングを確認
        """
        # APIエラーをモック
        mock_get_devices.return_value = (None, "SwitchBot API error: Connection failed")
        
        url = reverse('device-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "SwitchBot API error: Connection failed")
    
    def test_get_device_list_no_credentials(self):
        """
        資格情報がない場合のエラーハンドリングを確認
        """
        # 資格情報を削除
        self.credential.delete()
        
        url = reverse('device-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "SwitchBot credentials not registered.")


class DeviceStatusTests(APITestCase):
    """
    デバイスの状態取得のテスト
    """
    
    def setUp(self):
        # テスト用ユーザーを作成
        self.username = "devicestatususer"
        self.password = "devicestatuspass"
        self.user = User.objects.create_user(username=self.username, password=self.password)
        
        # SwitchBot資格情報を追加
        self.credential = SwitchBotCredential.objects.create(
            user=self.user,
            token="test-token-123",
            secret="test-secret-456"
        )
        
        # ログイン
        self.client = APIClient()
        url = reverse('login')
        data = {"username": self.username, "password": self.password}
        response = self.client.post(url, data, format="json")
        self.access_token = response.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        
        # テスト用デバイスID
        self.device_id = "test-device-123"
    
    @patch('api.utils.SwitchBotAPI.get_device_status')
    def test_get_device_status_success(self, mock_get_device_status):
        """
        デバイス状態の取得が成功することを確認
        """
        # APIレスポンスをモック
        mock_status = {
            "deviceId": "test-device-123",
            "deviceType": "Bot",
            "deviceMode": "pressMode",
            "power": "on",
            "battery": 95
        }
        mock_get_device_status.return_value = (mock_status, None)
        
        url = reverse('device-status', args=[self.device_id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["deviceId"], "test-device-123")
        self.assertEqual(response.data["deviceType"], "Bot")
        self.assertEqual(response.data["deviceMode"], "pressMode")
    
    @patch('api.utils.SwitchBotAPI.get_device_status')
    def test_get_device_status_error(self, mock_get_device_status):
        """
        APIからエラーが返された場合のハンドリングを確認
        """
        # APIエラーをモック
        mock_get_device_status.return_value = (None, "Device not found")
        
        url = reverse('device-status', args=[self.device_id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "Device not found")


class DeviceCommandTests(APITestCase):
    """
    デバイスへのコマンド送信テスト
    """
    
    def setUp(self):
        # テスト用ユーザーを作成
        self.username = "devicecommanduser"
        self.password = "devicecommandpass"
        self.user = User.objects.create_user(username=self.username, password=self.password)
        
        # SwitchBot資格情報を追加
        self.credential = SwitchBotCredential.objects.create(
            user=self.user,
            token="test-token-123",
            secret="test-secret-456"
        )
        
        # ログイン
        self.client = APIClient()
        url = reverse('login')
        data = {"username": self.username, "password": self.password}
        response = self.client.post(url, data, format="json")
        self.access_token = response.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        
        # テスト用デバイスIDとコマンド
        self.device_id = "test-device-123"
        self.command = "turnOn"
    
    @patch('api.utils.SwitchBotAPI.send_command')
    def test_send_command_success(self, mock_send_command):
        """
        コマンド送信が成功することを確認
        """
        # APIレスポンスをモック
        mock_response = {
            "statusCode": 100,
            "message": "success",
            "body": {}
        }
        mock_send_command.return_value = (mock_response, None)
        
        url = reverse('device-command', args=[self.device_id, self.command])
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["statusCode"], 100)
        self.assertEqual(response.data["message"], "success")
    
    @patch('api.utils.SwitchBotAPI.send_command')
    def test_send_command_with_param(self, mock_send_command):
        """
        パラメータ付きのコマンド送信が成功することを確認
        """
        # APIレスポンスをモック
        mock_response = {
            "statusCode": 100,
            "message": "success",
            "body": {}
        }
        mock_send_command.return_value = (mock_response, None)
        
        url = reverse('device-command', args=[self.device_id, "setAll"])
        response = self.client.post(url, {"param": "26,1,1,on"}, format="json")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["statusCode"], 100)
        mock_send_command.assert_called_with(self.user, self.device_id, "setAll", "26,1,1,on")
    
    @patch('api.utils.SwitchBotAPI.send_command')
    def test_send_command_error(self, mock_send_command):
        """
        APIからエラーが返された場合のハンドリングを確認
        """
        # APIエラーをモック
        mock_send_command.return_value = (None, "Command not supported")
        
        url = reverse('device-command', args=[self.device_id, self.command])
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "Command not supported")