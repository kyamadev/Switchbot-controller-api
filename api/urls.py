from django.urls import path
from .views import (
    RegisterView, LoginView, LogoutView,
    SwitchBotTokenView, DeviceListView, DeviceStatusView,
    DeviceCommandView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/', SwitchBotTokenView.as_view(), name='switchbot-token'),
    path('control/', DeviceListView.as_view(), name='device-list'),
    path('control/<str:deviceId>/', DeviceStatusView.as_view(), name='device-status'),
    path('control/<str:deviceID>/<str:command>/', DeviceCommandView.as_view(), name='device-command'),
]