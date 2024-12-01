from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import PacketCount
from .serializers import PacketCountSerializer

def index(request):
    data = PacketCount.objects.order_by('-timestamp')[:10]
    return render(request, 'monitor/index.html', {'data': data})

@api_view(['POST'])
def add_packet_count(request):
    serializer = PacketCountSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)
