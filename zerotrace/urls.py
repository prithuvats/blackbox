from django.urls import path
from . import views

urlpatterns = [
    path('',views.index,name='index'),
    path('about/', views.about, name='about'),
    path('scan/',  views.scan,  name='scan'),
    path('signup/',views.signup,name='signup'),
    path('login/',views.login,name='login'),
    path('dashboard/',views.dashboard,name='dashboard'),
    path('delete/',views.delete,name="delete"),
    path('changepassword/',views.changepassword,name="changepassword"),
    path("logout/",views.logout,name="logout"),
    path("forgotpassword/",views.forgotpasswords,name="forgotpasswords"),
    path("newpassword/",views.newpassword,name="newpassword")
]