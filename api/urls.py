from django.urls import path
from .views import (
    RegisterView, ActivateAccountView, LoginView, LogoutView,
    ResetPasswordView, ResetPasswordConfirmView, SwitchBotTokenView, DeviceListView, DeviceStatusView,
    DeviceCommandView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('activate/<str:token>/', ActivateAccountView.as_view(), name='activate'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('resetpassword/', ResetPasswordView.as_view(), name='resetpassword'),
    path('resetpassword_confirm/<str:token>/', ResetPasswordConfirmView.as_view(), name='reset_password_confirm'),
    path('token/', SwitchBotTokenView.as_view(), name='switchbot-token'),
    path('control/', DeviceListView.as_view(), name='device-list'),
    path('control/<str:deviceId>/', DeviceStatusView.as_view(), name='device-status'),
    path('control/<str:deviceID>/<str:command>/', DeviceCommandView.as_view(), name='device-command'),
]