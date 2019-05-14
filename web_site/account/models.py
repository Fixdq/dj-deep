from django.db import models

# Create your models here.
from base.BaseModel import BaseModel


class Stu(BaseModel):
    name = models.CharField(u'姓名', max_length=100,)
    stu_time = models.DateTimeField(verbose_name='学习时间')

    class Meta:
        db_table = "db_stu"
        verbose_name = 'student'
