import requests
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

AUTH_SERVICE_URL = "http://auth_service:8000/api/user/"

@api_view(['GET'])
def protected_resource(request):
    token = request.headers.get('Authorization')
    if not token:
        return Response({'detail': 'Missing token'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        user_response = requests.get(
            AUTH_SERVICE_URL,
            headers={'Authorization': token},
            timeout=5
        )
        if user_response.status_code != 200:
            return Response({'detail': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)

        user_data = user_response.json()
        return Response({
            'message': 'Access granted',
            'user': user_data
        })

    except requests.exceptions.RequestException:
        return Response({'detail': 'Auth service unavailable'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
