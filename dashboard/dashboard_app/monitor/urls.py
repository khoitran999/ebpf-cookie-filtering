from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('api/add_packet_count/', views.add_packet_count, name='add_packet_count'),
]
