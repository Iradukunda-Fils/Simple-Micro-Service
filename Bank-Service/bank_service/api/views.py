from rest_framework.decorators import api_view

AUTH_SERVICE_URL = "http://auth_service:8000/api/user/"


@api_view(["GET"])
def protected_resource(request): ...
    
    
