from django.db import models




class PacketInfo(models.Model):
    src_ip = models.CharField(max_length=100)
    dst_ip = models.CharField(max_length=100)
    src_port = models.IntegerField()
    dst_port = models.IntegerField()
    protocol = models.CharField(max_length=100)
    packet_type = models.CharField(max_length=100)
    packet_len = models.IntegerField()
    seq_num = models.IntegerField()
    ack_num = models.IntegerField()
    tcp_flags = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.src_ip} -> {self.dst_ip} ({self.protocol})"

class PacketCount(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    count = models.BigIntegerField()

    def __str__(self):
        return f"{self.timestamp}: {self.count}"
    

class Cookie(models.Model):
    cookie = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.cookie} - {self.timestamp}"

