from django.shortcuts import render
import json
import rsa
import base64
import random ,string,os
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from .settings import STATUS_CODE
from .models import user,inactivatedUser
from SafeLogin import settings
from Crypto.Cipher import AES
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

f=open('private.pem','r')
AESkey=b"fj*&29Jji8@@pP0$"
activeUserRandomRange="abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPRSTUVWXYZ0123456789"
MYURL="127.0.0.1:8000/bapi/"
privkey = rsa.PrivateKey.load_pkcs1(f.read().encode())
from .tools.emailSender import sendEmailForUserRegister

'''
预留手机登录接口
'''
def cellphoneLogin(request):
    pass

'''
用于用户注册（加密）
提交信息格式{}
TODO：
验证邮箱格式以及用户名格式
'''
@csrf_exempt
def register(request):
    #解密数据
    try:
        jMsg=_getRawData(request)
    except Exception as e:
        if settings.DEBUG ==True:
            print(e)
        resp = {'statuscode': STATUS_CODE["DATA_FORMAT_WRONG"], 'detail': 'data format fail'}
        return HttpResponse(json.dumps(resp), content_type="application/json")

    #验证用户是否存在
    if user.objects.filter(email=jMsg["email"]) or inactivatedUser.objects.filter(email=jMsg["email"]):
        resp = {'statuscode': STATUS_CODE["USER_EXIST"], 'detail': 'email had registered'}
        return HttpResponse(json.dumps(resp), content_type="application/json")

    #发送验证邮件
    rand_str = ''.join(random.sample(activeUserRandomRange+ string.digits, 20))  # The random string
    try:
        sendEmailForUserRegister(jMsg["email"],MYURL+"register/active/?email="+jMsg["email"]+"&key="+rand_str)
    except Exception as e:
        if settings.DEBUG == True:
            print(e)
        resp = {'statuscode': STATUS_CODE["EMAIL_SEND_FAIL"], 'detail': 'can\'t send email'}
        return HttpResponse(json.dumps(resp), content_type="application/json")

    #添加用户信息（未激活）
    newUser=inactivatedUser(username=jMsg["username"], passwordMd5=jMsg["password"],email=jMsg["email"],randomKey=rand_str)
    newUser.save()

    #返回成功信息
    resp = {'statuscode': STATUS_CODE["SUCCEED"], 'detail': 'Register success'}
    return HttpResponse(json.dumps(resp), content_type="application/json")
'''
激活用户账户的操作
用于用户邮箱收到的链接
'''
def registerActive(request):
    print(request.GET)
    if request.GET:
        activeuser=inactivatedUser.objects.filter(email=request.GET["email"],randomKey=request.GET["key"])
        if activeuser:
            activeuser=activeuser[0]
            newUser = user(username=activeuser.username, passwordMd5=activeuser.passwordMd5, email=activeuser.email, flag=0)
            activeuser.delete()
            newUser.save()
            #这里应该返回一个网页
            resp = {'statuscode': STATUS_CODE["SUCCEED"], 'detail': '激活成功'}
            return HttpResponse(json.dumps(resp), content_type="application/json")
    resp = {'statuscode': STATUS_CODE["UNKNOW_ERROR"], 'detail': '激活链接错误'}
    return HttpResponse(json.dumps(resp), content_type="application/json")

    pass
'''
登录
'''
@csrf_exempt
def login(request):
    #解密数据
    try:
        jMsg=_getRawData(request)
    except Exception as e:
        if settings.DEBUG ==True:
            print(e)
        resp = {'statuscode': STATUS_CODE["DATA_FORMAT_WRONG"], 'detail': 'data format fail'}
        return HttpResponse(json.dumps(resp), content_type="application/json")

    #连续登录检测

    #查找用户

    #把用户信息和session关联起来

    if 'test' in request.session:
        print(request.session['test'])
    request.session["test"]="test"

    resp = {'statuscode':STATUS_CODE["SUCCEED"], 'detail': 'Get success'}
    return HttpResponse(json.dumps(resp), content_type="application/json")

# '''产生验证码的'''
# def captcha(request):
#     '''Captcha'''
#     image = Image.new('RGB', (147, 49), color = (255, 255, 255)) # model, size, background color
#     font_file = os.path.join(BASE_DIR, 'Blog/static/Blog/ttf/Arial.ttf') # choose a font file
#     font = ImageFont.truetype(font_file, 47) # the font object
#     draw = ImageDraw.Draw(image)
#     rand_str = ''.join(random.sample(myRandomRange + string.digits, 4)) # The random string
#     request.session["captcha"]=rand_str
#     chance = min(100, max(0, 20))  # 大小限制在[0, 100]
#
#     for w in range(147):
#         for h in range(49):
#             tmp = random.randint(0, 100)
#             if tmp > 100 - chance:
#                 draw.point((w, h), fill=(0, 0, 0))
#     draw.text((7, 0), rand_str, fill=(0, 0, 0), font=font) # position, content, color, font
#     line_num = random.randint(*(20, 50))  # 干扰线条数
#
#     for i in range(line_num):
#         # 起始点
#         begin = (random.randint(0, 147), random.randint(0, 49))
#         # 结束点
#         end = (random.randint(0, 147), random.randint(0,49))
#         draw.line([begin, end], fill=(0, 0, 0))
#
#     del draw
#     request.session['captcha'] = rand_str.lower() # store the content in Django's session store
#     buf = BytesIO()# a memory buffer used to store the generated image
#
#     image.save(buf, 'jpeg')
#     return HttpResponse(buf.getvalue(), 'image/jpeg') # return th

'''
获得未加密的数据
input：request
return:字典格式
'''
def _getRawData(request):
    print(request.body.decode())
    data=json.loads(request.body.decode())
    params = data["params"]
    encSecKey = data["encSecKey"]
    params = base64.b64decode(params)
    secKey = rsa.decrypt(base64.b64decode(encSecKey), privkey)
    cipher1 = AES.new(secKey, AES.MODE_ECB)
    t_params = cipher1.decrypt(params)
    for i in range(len(t_params) - 1, 0, -1):
        if t_params[i] is not t_params[len(t_params) - 1]:
            t_params = t_params[:i + 1]
            break
    cipher = AES.new(AESkey, AES.MODE_ECB)
    msg = cipher.decrypt(t_params)
    for i in range(len(msg) - 1, 0, -1):
        if msg[i] is not msg[len(t_params) - 1]:
            msg = msg[:i + 1]
            break
    return json.loads(msg.decode())