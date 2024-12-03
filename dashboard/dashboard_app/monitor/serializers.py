from rest_framework import serializers
from .models import PacketCount, PacketInfo

class PacketCountSerializer(serializers.ModelSerializer):
    class Meta:
        model = PacketCount
        fields = ['timestamp', 'count']

class PacketInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = PacketInfo
        fields = '__all__'
