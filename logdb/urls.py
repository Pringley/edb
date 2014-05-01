from django.conf.urls import include, url
from rest_framework import routers, urls as drf_urls

from logdb import views

router = routers.DefaultRouter()
router.register(r'packets', views.PacketViewSet)

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^compute/average', views.average),
    url(r'^compute/count', views.count),
    url(r'^compute/correlate', views.correlate),
]
