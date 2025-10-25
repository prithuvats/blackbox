from django.db import models

# Create your models here.



class users(models.Model):
  fullname = models.CharField(max_length=255)
  phone = models.CharField(max_length=255)
  email=models.EmailField(unique=True)#unique make the django to never allow top duplicate email store in tje data bsae
  username=models.CharField(max_length=255)
  password=models.CharField(max_length=255)




class forgotpassword(models.Model):
  email=models.EmailField(unique=True)
  otp=models.CharField(unique=True)
