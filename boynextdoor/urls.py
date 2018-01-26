from django.conf.urls import url,include
from . import views
urlpatterns = [
  url(r'login/cellphone/', views.cellphoneLogin, name='cellphoneLogin'),
  url(r'login/', views.login, name='Login'),
  url(r'register/active/', views.registerActive, name='Login'),
  url(r'register/', views.register, name='Login'),

]