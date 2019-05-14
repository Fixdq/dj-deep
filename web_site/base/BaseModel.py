from django.db import models


class BaseModel(models.Model):
    """
    模型基类
    """
    id = models.CharField(u'ID', help_text=u'ID', primary_key=True, max_length=30, blank=True)
    STATUS_VALID = 0
    STATUS_INVALID = 1
    STATUS_REVIEW = 2

    STATUS_TYPE = (
        (STATUS_VALID, '有效'),
        (STATUS_INVALID, '无效'),
        (STATUS_REVIEW, '待审核'),
    )

    status = models.IntegerField(u'状态', help_text=u'状态', default=STATUS_REVIEW, choices=STATUS_TYPE)
    create_time = models.DateTimeField(u'创建时间', help_text=u'创建时间', auto_now_add=True)
    update_time = models.DateTimeField(u'最后修改时间', help_text=u'最后修改时间', auto_now=True)

    class Meta:
        abstract = True
