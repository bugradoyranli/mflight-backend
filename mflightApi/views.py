from django.shortcuts import render
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .serializers import UserSerializer
import jwt,datetime
from jwt.exceptions import ExpiredSignatureError, DecodeError
from rest_framework.permissions import IsAuthenticated,AllowAny
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.core.cache import cache  
from django.contrib.auth.models import User
import re
from django.core.exceptions import ValidationError
from django.conf import settings


class RegisterUser(APIView):  
    permission_classes = [AllowAny]   #user doesnt need to have access token for access this class    
    def post(self, request): 
        password = request.data.get("password")  
                                     
        serializer = UserSerializer(data=request.data)              
        if serializer.is_valid():                     #checks username and email is valid              
            try:
                enforcingStrongPassword(password)  
            except ValidationError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            user = serializer.save()
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LoginUser(APIView):     
    permission_classes=[AllowAny]    #doesnt need to have access token
    def post(self, request):                    
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)              
        if user:                                                           #creating jwt after authenticate user
            
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
   
class LogoutUser(APIView):
    permission_classes=[IsAuthenticated]
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')        #getting json format refresh token
            if refresh_token:
                token = RefreshToken(refresh_token)                 
                token.blacklist()                                    #adding refresh token into blacklist
                return Response({"message": "Logout successful"}, status=200)       
            return Response({"error": "Refresh token is required"}, status=400)
        except Exception as e:
            return Response({"error": str(e)}, status=400)
        



class RetrieveProfile(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
      
        user = request.user  #Authenticated user
        serializer = UserSerializer(user)
        return Response(serializer.data) 

class UpdateProfile(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user  #authenticated user
        password = request.data.get('password')
        if password:
            return Response({"message": "Password change is not allowed."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = UserSerializer(user, data=request.data, partial=True) 

        if serializer.is_valid():
            serializer.save()  
            return Response({"message": "Profile updated successfully"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  
    
class ChangePasswordRequest(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        #authenticated user
        user = request.user
        email = user.email  

        try:
            #Creating userid and token
            uid = urlsafe_base64_encode(str(user.pk).encode())  
            token = PasswordResetTokenGenerator().make_token(user)  
                                                                            
            reset_url = f"http://{get_current_site(request).domain}/api/post/reset-password/{uid}/{token}/" #url for resetting password
                                                                             
            message = render_to_string("reset_password_email.html", { #creating email content
                "user": user,
                "reset_url": reset_url,
            })

               #MAIL SENDING FUNCTION
            send_mail(
                "Password Reset Request",  # Email Subject
                message,                   # Email content
                settings.EMAIL_HOST_USER,  # Sender email adress
                [email] ,                 # Reciever email adress 
                fail_silently=False,  # Handle errors gracefully
                html_message=message     
            )

            
            return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"message": f"An error occured: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        

class ResetPassword(APIView):
    permission_classes = [AllowAny]
    def post(self, request, uid, token):
        try:
            # Decoding userId
           
            uid = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=uid)
            
            # Verifying token
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({"message": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
            
            #Getting new password
            newPassword = request.data.get("new_password")

            if not newPassword:
                return Response({"message": "New password is required"}, status=status.HTTP_400_BAD_REQUEST)
             #Enforcing strong pasword   
            strongPassword= enforcingStrongPassword(newPassword)                     
            #Updating password and saving     
            user.set_password(strongPassword)              
            user.save()

            return Response({"message": "Password has been reset successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": f"An error occurred: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        


def enforcingStrongPassword(password):
      if len(password) < 8:
          raise ValidationError("Password must be at least 8 characters long.")
      if not re.search(r"[A-Z]", password):
          raise ValidationError("Password must contain at least one uppercase letter.")
      if not re.search(r"[a-z]", password):
          raise ValidationError("Password must contain at least one lowercase letter.")
      if not re.search(r"[0-9]", password):
          raise ValidationError("Password must contain at least one number.")
      if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
          raise ValidationError("Password must contain at least one special character.")
      
      return password