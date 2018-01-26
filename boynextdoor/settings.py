'''
定义status code
如果服务器内部错误是可以直接在java中报错的
'''
STATUS_CODE={
    "SUCCEED":200,
    #login
    "PASSWOED_WRONG":601,
    "USER_NOT_FOUND":602,
    "USER_NOT_ACTIVE":603,
    #register
    "USER_EXIST":701,
    "EMAIL_ADDR_WRONG":702,
    "EMAIL_SEND_FAIL":703,
    #verification code
    "VERIFICATION_CODE_WRONG":801,
    #global
    #server error
    "UNKNOW_ERROR":900,
    "DATA_FORMAT_WRONG":901,
}