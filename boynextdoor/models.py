from django.db import models
from django.utils import timezone
# Create your models here.
class user(models.Model):
    username=models.CharField(max_length=20)
    passwordMd5=models.CharField(max_length=24)
    email=models.EmailField(primary_key=True)
    registerDate = models.DateTimeField('用户创建时间', default=timezone.now)
    lastLoginDate=models.DateTimeField('登录时间', default=timezone.now)
    #lastLodinIp
    flag=models.IntegerField()
class inactivatedUser(models.Model):
    username = models.CharField(max_length=20)
    passwordMd5 = models.CharField(max_length=24)
    email = models.EmailField(primary_key=True)
    registerDate = models.DateTimeField('用户创建时间', default=timezone.now)
    randomKey=models.CharField(max_length=20)#所以可以用一个随机数加上email地址来激活hhhh