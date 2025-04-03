from unittest.mock import patch
from django.urls import reverse
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APITestCase, APIClient, APIRequestFactory
from django.contrib.auth import get_user_model
from api.models import SwitchBotCredential
from django.core.cache import cache
from api.rate_limiter import RateLimiter
from api.utils import SwitchBotAPI
from unittest.mock import patch, MagicMock

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

class EncryptionTest(TestCase):
    """
    SwitchBot認証情報の暗号化と復号化のテスト
    """
    
    def setUp(self):
        self.user = User.objects.create_user(
            username="testencryption",
            password="testpass123"
        )
        
    def test_encryption_decryption_process(self):
        """
        認証情報が保存時に適切に暗号化され、取得時に復号化されることを確認
        """
        # 元の平文値
        original_token = "test-token-123"
        original_secret = "test-secret-456"
        
        # 認証情報を作成
        credential = SwitchBotCredential.objects.create(
            user=self.user,
            token=original_token,
            secret=original_secret
        )
        
        # 正しいレコードをテストしていることを確認するためのトークンID
        cred_id = credential.id
        
        # DjangoのORMキャッシュをクリアして、DBから確実に取得するようにする
        from django.db import connection
        connection.close()
        
        # データベースから再取得
        refetched_cred = SwitchBotCredential.objects.get(id=cred_id)
        
        # 値がアクセス時に自動的に復号化されることを確認
        self.assertEqual(refetched_cred.token, original_token)
        self.assertEqual(refetched_cred.secret, original_secret)
        
    def test_switchbot_api_uses_decrypted_values(self):
        """
        SwitchBotAPIが復号化された認証情報の値を適切に使用することを確認
        """
        # 認証情報を作成
        SwitchBotCredential.objects.create(
            user=self.user,
            token="test-token-123",
            secret="test-secret-456"
        )
        
        # SwitchBotAPIを使用してヘッダーを取得
        headers = SwitchBotAPI.get_headers(self.user)
        
        # Authorizationヘッダーに復号化されたトークンが含まれていることを確認
        self.assertEqual(headers["Authorization"], "test-token-123")
        
        # 署名はタイムスタンプを含むため直接検証できないが、
        # 生成されていることを確認（シークレットがアクセス可能であることを示す）
        self.assertIn("sign", headers)
        self.assertTrue(headers["sign"])  # 空でない文字列

class RateLimitTest(TestCase):
    """
    APIレート制限機能のテスト
    """
    
    def setUp(self):
        self.user = User.objects.create_user(
            username="testlimit",
            password="testpass123"
        )
        self.factory = APIRequestFactory()
        # 各テスト開始時にキャッシュをクリア
        cache.clear()
        
    def tearDown(self):
        # 各テスト終了時にキャッシュをクリア
        cache.clear()
    
    def test_user_daily_limit(self):
        """
        ユーザーの日次制限が正しく機能することをテスト
        """
        # モックビュー関数を作成
        mock_view = MagicMock(return_value="OK")
        
        # デコレータ付きのビューを作成
        decorated_view = RateLimiter.limit_api_calls(mock_view)
        
        # リクエストを制限直前までシミュレート
        request = self.factory.get('/')
        request.user = self.user
        
        # キャッシュを設定して制限に近づいていることをシミュレート
        user_daily_key = f"switchbot_daily_limit_{self.user.id}"
        cache.set(user_daily_key, 999, timeout=86400)  # 999リクエスト
        
        # このリクエストは成功するはず（合計1000になる）
        response = decorated_view(self, request)
        self.assertEqual(response, "OK")  # 元のビューの戻り値
        
        # このリクエストはレート制限されるはず
        response = decorated_view(self, request)
        self.assertEqual(response.status_code, 429)  # リクエスト過多
        self.assertEqual(response.data["detail"], "1日のAPI呼び出し制限に達しました。明日再試行してください。")
    
    def test_device_short_term_limit(self):
        """
        デバイス固有の短期レート制限が正しく機能することをテスト
        """
        # モックビュー関数を作成
        mock_view = MagicMock(return_value="OK")
        
        # デコレータ付きのビューを作成
        decorated_view = RateLimiter.limit_api_calls(mock_view)
        
        # 特定のデバイスに対するリクエストをシミュレート
        request = self.factory.get('/')
        request.user = self.user
        
        # キャッシュを設定してデバイス制限に近づいていることをシミュレート
        device_id = "test-device-123"
        device_key = f"switchbot_device_limit_{device_id}"
        cache.set(device_key, 9, timeout=15)  # 直近15秒間に9回のリクエスト
        
        # このリクエストは成功するはず（合計10になる）
        response = decorated_view(self, request, deviceId=device_id)
        self.assertEqual(response, "OK")  # 元のビューの戻り値
        
        # このリクエストはレート制限されるはず
        response = decorated_view(self, request, deviceId=device_id)
        self.assertEqual(response.status_code, 429)  # リクエスト過多
        self.assertEqual(response.data["detail"], "デバイスへのリクエストが多すぎます。少し待ってから再試行してください。")