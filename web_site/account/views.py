from django.utils import timezone
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from account.serializers import StuSerializer
from base import utils
from .models import Stu


# Create your views here.

class TestApiView(APIView):

    def get(self, request):
        return Response('ok')


class DateTimeTestView(ListAPIView):
    serializer_class = StuSerializer

    def post(self, request, *args, **kwargs):
        Stu.objects.create(name='', stu_time=timezone.now())
        return Response('ok')

    def get(self, request, *args, **kwargs):
        dt_start = request.query_params.get('dt_start')
        dt_end = request.query_params.get('dt_end')
        dt_start = utils.string_time(dt_start, '%Y-%m-%d %H:%M:%S')
        dt_end = utils.string_time(dt_end, '%Y-%m-%d %H:%M:%S')
        dt_start = timezone.make_aware(dt_start)
        dt_end = timezone.make_aware(dt_end)
        self.queryset = Stu.objects.filter(stu_time__range=[dt_start, dt_end])
        return self.list(self, request, *args, **kwargs)
