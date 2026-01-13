# api/management/commands/create_initial_data.py
from django.core.management.base import BaseCommand
from api.models import SubscriptionPlan, UserProfile

class Command(BaseCommand):
    help = 'Creates initial subscription plans and updates user profiles'
    
    def handle(self, *args, **options):
        # Create subscription plans
        plans = [
            {
                'name': 'Free',
                'stripe_price_id': 'free_tier',
                'monthly_price': 0.00,
                'daily_message_limit': 50,
                'requests_per_minute': 5,
                'features': ['50 messages/day', 'Basic AI assistance', 'Study tracking']
            },
            {
                'name': 'Premium',
                'stripe_price_id': 'price_premium',
                'monthly_price': 9.99,
                'daily_message_limit': 1000,
                'requests_per_minute': 30,
                'features': ['1000 messages/day', 'Priority responses', 'Advanced analytics']
            },
            {
                'name': 'Unlimited',
                'stripe_price_id': 'price_unlimited',
                'monthly_price': 19.99,
                'daily_message_limit': 5000,
                'requests_per_minute': 100,
                'features': ['5000 messages/day', 'Unlimited subjects', 'Priority support']
            }
        ]
        
        for plan_data in plans:
            plan, created = SubscriptionPlan.objects.get_or_create(
                name=plan_data['name'],
                defaults=plan_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'Created plan: {plan.name}'))
            else:
                self.stdout.write(f'Plan already exists: {plan.name}')
        
        # Update user profiles
        profiles = UserProfile.objects.all()
        for profile in profiles:
            profile.update_limits()
            profile.save()
        
        self.stdout.write(self.style.SUCCESS(
            f'Updated {profiles.count()} user profiles'
        ))
        
        # Show summary
        self.stdout.write('\n' + '='*50)
        self.stdout.write('SUBSCRIPTION PLANS SUMMARY:')
        self.stdout.write('='*50)
        for plan in SubscriptionPlan.objects.all():
            self.stdout.write(
                f'{plan.name:<15} | ${plan.monthly_price:<6} | '
                f'{plan.daily_message_limit:<5} msgs/day | '
                f'{plan.requests_per_minute:<3} req/min'
            )