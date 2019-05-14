# -- coding: utf-8 --
from rest_framework import serializers
from django.utils.timezone import localtime
from account.models import Stu


class StuSerializer(serializers.ModelSerializer):
    stu_date = serializers.SerializerMethodField

    def get_stu_date(self, obj):

        return localtime(obj.stu_time)

    class Meta:
        model = Stu
        fields = '__all__'
