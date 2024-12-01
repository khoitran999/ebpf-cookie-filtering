from rest_framework import serializers
from .models import PacketCount

class PacketCountSerializer(serializers.ModelSerializer):
    class Meta:
        model = PacketCount
        fields = ['timestamp', 'count']
