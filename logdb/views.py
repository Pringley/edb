from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.exceptions import APIException

from edb import crypto, paillier
from edb.server import util
from edb.server.mixins import EncryptedSearchMixin
from logdb.serializers import PacketSerializer
from logdb.models import Packet

class PubKeyRequired(APIException):
    status_code = 403
    default_detail = "must provide public key for homomorphic operations"

@api_view(['GET'])
def average(request):
    params = request.QUERY_PARAMS.dict()

    # get the paillier key
    modulus = params.pop('modulus', None)
    generator = params.pop('generator', None)
    if modulus is None or generator is None:
        raise PubKeyRequired
    try:
        modulus = int(modulus)
        generator = int(generator)
    except ValueError:
        raise PubKeyRequired("invalid public key")
    key = paillier.PublicKey(modulus, generator)

    packets = Packet.objects.encrypted_filter(**params)
    try:
        lengths = [int(packet.length) for packet in packets]
    except ValueError:
        raise APIException("invalid database state -- non-int packet lengths")

    ctxt_sum, ctxt_count = paillier.average(key, lengths)

    return Response({'sum': ctxt_sum, 'count': ctxt_count})

@api_view(['GET'])
def count(request):
    params = request.QUERY_PARAMS.dict()
    packets = Packet.objects.encrypted_filter(**params)
    return Response({'count': len(packets)})


# CRUD view with encrypted search
class PacketViewSet(EncryptedSearchMixin, viewsets.ModelViewSet):
    model = Packet
    queryset = Packet.objects.all()
    serializer_class = PacketSerializer
