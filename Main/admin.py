from django.contrib import admin
from . import models

admin.site.register(models.UserDetails)
admin.site.register(models.EmergencyDetails)