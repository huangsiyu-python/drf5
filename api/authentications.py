from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from api.models import User

# 游客登录验证
class MyAuth(BaseAuthentication):
    def authenticate(self, request):
        auth = request.META.get('HTTP_AUTHORIZATION', None)
        # print(auth)
        if auth is None:
            return None
        auth_list = auth.split()
        if not (len(auth_list)==2 and auth_list[0].lower()=="auth"):
            raise exceptions.AuthenticationFailed("认证信息有误")
        if auth_list[1] != "abc.marry.123":
            raise exceptions.AuthenticationFailed("用户信息校验失败")
        user=User.objects.filter(username="admin").first()
        if not user:
            raise exceptions.AuthenticationFailed("用户不存在")
        print(user)
        return (user, None)
