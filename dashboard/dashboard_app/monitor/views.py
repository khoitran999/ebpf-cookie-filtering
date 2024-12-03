from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
import ctypes
from .models import PacketCount, PacketInfo
from .serializers import PacketCountSerializer, PacketInfoSerializer

# class PacketInfo(ctypes.Structure):
#             _fields_ = [
#                 ("src_ip", ctypes.c_uint32),
#                 ("dst_ip", ctypes.c_uint32),
#                 ("src_port", ctypes.c_uint16),
#                 ("dst_port", ctypes.c_uint16),
#                 ("protocol", ctypes.c_uint8),
#                 ("packet_type", ctypes.c_uint8),
#                 ("packet_len", ctypes.c_uint32),
#                 ("seq_num", ctypes.c_uint32),
#                 ("ack_num", ctypes.c_uint32),
#                 ("tcp_flags", ctypes.c_uint8),
#             ]

# class PacketInfo:
#     def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, packet_type, packet_len, seq_num, ack_num, tcp_flags):
#         self.src_ip = src_ip
#         self.dst_ip = dst_ip
#         self.src_port = src_port
#         self.dst_port = dst_port
#         self.protocol = protocol
#         self.packet_type = packet_type
#         self.packet_len = packet_len
#         self.seq_num = seq_num
#         self.ack_num = ack_num
#         self.tcp_flags = tcp_flags

def index(request):
    data = PacketCount.objects.order_by('-timestamp')[:10]
    # auto reload every 2 seconds
    packets = PacketInfo.objects.order_by('-timestamp')[:10]
    return render(request, 'monitor/index.html', {
        'data': data,
        'packets': packets
        })

@api_view(['POST'])
def add_packet_count(request):
    serializer = PacketCountSerializer(data=request.data)
    packets_received = request.data['packets']
    if serializer.is_valid():
        serializer.save()
        for packet in packets_received:
            packet_serializer = PacketInfoSerializer(data=packet)
            if packet_serializer.is_valid():
                packet_serializer.save()
            else:
                print(packet_serializer.errors)
        return Response("Success", status=201)
    return Response(serializer.errors, status=400)
