#!/usr/bin/env python3
# coding: utf-8
import smtplib
from email.mime.text import MIMEText


def sendEmailForUserRegister(EmailAddr,link):
    sender = 'XXX'
    receiver = [EmailAddr]
    subject = '用户注册验证'
    smtpserver = 'smtp.sina.com'
    username = 'XXX'
    password = 'XXX'
    msg = MIMEText('<html><h1>你好您在XXX应用注册了用户但是需要点击以下链接激活。如不是本人操作请忽略。</h1>'
                   '<a href='+link+'>'+link+'</a>'
                   '</html>', 'html', 'utf-8')
    msg['Subject'] = subject
    msg['from'] = 'XXX'
    smtp = smtplib.SMTP()
    smtp.connect(smtpserver)
    smtp.login(username, password)
    smtp.sendmail(sender, receiver, msg.as_string())
    smtp.quit()