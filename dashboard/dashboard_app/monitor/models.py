from django.db import models

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

