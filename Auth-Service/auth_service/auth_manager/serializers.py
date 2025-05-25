from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer

class AuthTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        # Add custom claims
        data['user_type'] = self.user.user_type if hasattr(self.user, 'user_type') else 'unknown'
        data['email'] = self.user.email
        data['username'] = self.user.username

        return data

class AuthTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        # Decode token to read data (optional)
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken(attrs['refresh'])

        data['username'] = str(refresh['username']) if 'username' in refresh else 'unknown'
        return data