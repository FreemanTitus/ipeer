from django.urls import path
from . import consumers
from . import views


app_name = 'chat'
websocket_urlpatterns = [
    path('chat_ws/', consumers.ChatConsumer.as_asgi()),
]

urlpatterns = [
    path('messages/', views.MessageModelList.as_view(), name='all_messages_list'),
    path('message/<room_with>/', views.MessageModelList.as_view(), name='messages_list'),
    path('rooms/', views.RoomModelList.as_view(), name='rooms_list'),
    path('self/', views.SelfInfoView.as_view(), name='self_info'),
    path('upload/', views.UploadView.as_view(), name='fileupload'),
]