"""
URL configuration for mflightApi project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from .views import *


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/register/', RegisterUser.as_view(), name='register'),
    path('api/login/',LoginUser.as_view(),name='login'),
    path('api/logout/',LogoutUser.as_view(),name='logout'),
    path('api/getprofile/',RetrieveProfile.as_view(),name='getprofile'),
    path('api/post/profile/updateprofile/',UpdateProfile.as_view(),name='updateprofile'),
    path('api/post/profile/changepassword/',ChangePasswordRequest.as_view(),name='changepassword'),          
    path('api/post/reset-password/<str:uid>/<str:token>/', ResetPassword.as_view(), name='reset-password')
]