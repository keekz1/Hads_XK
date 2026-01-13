from django.contrib import admin
from .models import UserProfile, Subject, StudySession

admin.site.register(UserProfile)
admin.site.register(Subject)
admin.site.register(StudySession)
