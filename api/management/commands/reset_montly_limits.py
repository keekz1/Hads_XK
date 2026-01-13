# Create a file: api/management/commands/reset_monthly_limits.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth.models import User
from api.models import UserProfile

class Command(BaseCommand):
    help = 'Reset monthly usage limits for all users'
    
    def handle(self, *args, **options):
        today = timezone.now().date()
        reset_count = 0
        
        for profile in UserProfile.objects.all():
            if profile.monthly_reset_date and today >= profile.monthly_reset_date:
                profile.pdf_analyses_this_month = 0
                profile.data_analyses_this_month = 0
                profile.tokens_this_month = 0
                
                # Set next reset date
                next_month = today.replace(day=28) + timezone.timedelta(days=4)
                profile.monthly_reset_date = next_month.replace(day=1)
                
                profile.save()
                reset_count += 1
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully reset monthly limits for {reset_count} users')
        )