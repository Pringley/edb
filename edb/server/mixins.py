from rest_framework.views import APIView
from rest_framework.response import Response

class EncryptedSearchMixin:
    """Mix into a ViewSet to allow encrypted GET search queries."""

    def list(self, request):
        params = request.QUERY_PARAMS.dict()
        results = self.model.objects.encrypted_filter(**params)
        serializer = self.serializer_class(results, many=True)
        return Response(serializer.data)
