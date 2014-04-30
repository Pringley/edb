from rest_framework import viewsets

from edb.server.mixins import EncryptedSearchMixin
from logdb.serializers import PacketSerializer
from logdb.models import Packet

class PacketViewSet(EncryptedSearchMixin, viewsets.ModelViewSet):
    model = Packet
    queryset = Packet.objects.all()
    serializer_class = PacketSerializer
