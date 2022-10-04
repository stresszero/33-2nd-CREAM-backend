import jwt, requests

from django.http import JsonResponse
from django.conf import settings

from users.models import User

def login_decorator(func):
    def wrapper(self, request, *args, **kwargs):
        try:
            access_token = request.headers.get('Authorization')
            payload      = jwt.decode(access_token, settings.SECRET_KEY, algorithms=settings.ALGORITHM)
            request.user = User.objects.get(id=payload['id'])

            return func(self, request, *args, **kwargs)

        except User.DoesNotExist:
            return JsonResponse({'message': 'USER_NOT_EXIST'}, status=400)
            
        except jwt.DecodeError:
            return JsonResponse({'message': 'INVALID_TOKEN'}, status=400)

        except KeyError:
            return JsonResponse({'message': 'KEY_ERROR'}, status=400)

    return wrapper

class KakaoLoginAPI:
    def __init__(self, client_id):
        self.client_id       = client_id
        self.kakao_token_uri = "https://kauth.kakao.com/oauth/token"
        self.kakao_user_uri  = "https://kapi.kakao.com/v2/user/me"
        self._access_token   = None

    def get_kakao_token(self, code):
        body = {
            "grant_type"  : "authorization_code",
            "client_id"   : self.client_id,
            "redirect_uri": settings.KAKAO_REDIRECT_URI,
            "code"        : code,
        }

        response = requests.post(self.kakao_token_uri, data=body, timeout=3)

        if response.status_code != 200:
            return JsonResponse({'message': 'INVALID_RESPONSE'}, status=response.status_code)

        self._access_token = response.json()["access_token"]
        
    def get_kakao_profile(self):
        response = requests.post(
            self.kakao_user_uri,
            headers = {
                "Authorization": f"Bearer {self._access_token}"
            }, timeout=3
        )

        if response.status_code != 200:
            return JsonResponse({'message': 'INVALID_RESPONSE'}, status=response.status_code)

        return response.json()