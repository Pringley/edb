from rest_framework import serializers

from logdb.models import Packet

class PacketSerializer(serializers.ModelSerializer):
    class Meta:
        model = Packet
