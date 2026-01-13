from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    UserProfile, StudyContent, AIConversation, 
    SubscriptionPlan, APIProxyLog, RateLimitLog,
    BillingTransaction, APIAutoSetupRequest, ProfitAnalytics,
    UserSubscription, Reseller, ResellerClient, ResellerCommission, ResellerPayout
)
from django.utils import timezone

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'date_joined', 'is_staff']
        read_only_fields = ['date_joined', 'is_staff']

# Update the UserProfileSerializer to remove fields that don't exist in the model anymore
class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    usage_percentage = serializers.SerializerMethodField()
    messages_remaining = serializers.SerializerMethodField()
    subscription_status = serializers.CharField(read_only=True)
    has_api_key = serializers.SerializerMethodField()
    your_profit_info = serializers.SerializerMethodField()
    reseller_info = serializers.SerializerMethodField()
    
    class Meta:
        model = UserProfile
        fields = [
            'id', 'user', 'username', 'bio', 'level', 'created_at',
            'subscription_tier', 'subscription_status',
            'preferred_provider', 'preferred_model',
            'openai_api_key', 'groq_api_key',  # Removed anthropic_api_key and gemini_api_key
            'requests_today', 'tokens_this_month',
            'pdf_analyses_this_month', 'data_analyses_this_month',
            'last_active', 'usage_percentage', 'messages_remaining',
            'stripe_customer_id', 'current_period_start', 'current_period_end',
            'has_api_key', 'your_profit_info', 'reseller_code_used',
            'referred_by_code', 'reseller_info',
            'openai_key_type', 'openai_key_credit_balance', 'openai_account_status'  # Added OpenAI specific fields
        ]
        read_only_fields = [
            'created_at', 'last_active', 'requests_today',
            'tokens_this_month', 'usage_percentage', 'messages_remaining'
        ]
    
    def get_usage_percentage(self, obj):
        limits = obj.get_tier_limits()
        if limits['daily_requests'] == 0:
            return 0
        return min(100, (obj.requests_today / limits['daily_requests']) * 100)
    
    def get_messages_remaining(self, obj):
        limits = obj.get_tier_limits()
        return max(0, limits['daily_requests'] - obj.requests_today)
    
    def get_has_api_key(self, obj):
        return obj.has_api_key()
    
    def get_your_profit_info(self, obj):
        return obj.get_your_profit()
    
    def get_reseller_info(self, obj):
        """Get reseller information if user is linked to a reseller"""
        try:
            reseller_client = ResellerClient.objects.get(user=obj.user)
            return {
                'is_reseller_client': True,
                'reseller_id': reseller_client.reseller.id,
                'reseller_name': reseller_client.reseller.name,
                'reseller_code': reseller_client.reseller.code,
                'commission_rate': float(reseller_client.commission_rate),
                'status': reseller_client.status,
                'joined': reseller_client.created_at.isoformat()
            }
        except ResellerClient.DoesNotExist:
            return {'is_reseller_client': False}
    
    def update(self, instance, validated_data):
        # Handle nested user data if provided
        user_data = validated_data.pop('user', None)
        if user_data:
            user_serializer = UserSerializer(instance.user, data=user_data, partial=True)
            if user_serializer.is_valid():
                user_serializer.save()
        
        # Update profile
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        return instance
# api/serializers.py
from rest_framework import serializers
from .models import UploadedDocument

class UploadedDocumentSerializer(serializers.ModelSerializer):
    file_size_mb = serializers.SerializerMethodField()
    preview = serializers.SerializerMethodField()
    
    class Meta:
        model = UploadedDocument
        fields = ['id', 'file_name', 'file_type', 'file_size', 'file_size_mb', 
                  'uploaded_at', 'page_count', 'is_processed', 'preview']
        read_only_fields = fields
    
    def get_file_size_mb(self, obj):
        return obj.file_size_mb
    
    def get_preview(self, obj):
        if obj.extracted_text:
            return obj.extracted_text[:500] + "..." if len(obj.extracted_text) > 500 else obj.extracted_text
        return None
class StudyContentSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True, default=serializers.CurrentUserDefault())
    username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = StudyContent
        fields = [
            'id', 'user', 'username', 'title', 'content', 'subject',
            'difficulty', 'ai_generated', 'ai_model_used',
            'estimated_user_token_cost', 'created_at'
        ]
        read_only_fields = [
            'created_at', 'ai_generated', 'ai_model_used',
            'estimated_user_token_cost'
        ]
    
    def create(self, validated_data):
        # Automatically set the user to the current user
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)

class AIConversationSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True, default=serializers.CurrentUserDefault())
    username = serializers.CharField(source='user.username', read_only=True)
    token_cost = serializers.SerializerMethodField()
    your_profit = serializers.SerializerMethodField()
    is_free = serializers.SerializerMethodField()
    
    class Meta:
        model = AIConversation
        fields = [
            'id', 'user', 'username', 'prompt', 'response', 'subject',
            'difficulty', 'model_used', 'input_tokens', 'output_tokens',
            'total_tokens', 'estimated_user_cost', 'your_service_fee',
            'your_profit', 'api_provider', 'response_time_ms',
            'was_cached', 'cache_hit', 'user_tier_at_time', 'created_at',
            'token_cost', 'is_free'
        ]
        read_only_fields = [
            'created_at', 'model_used', 'estimated_user_cost',
            'response_time_ms', 'was_cached', 'cache_hit',
            'user_tier_at_time', 'input_tokens', 'output_tokens',
            'total_tokens', 'your_service_fee', 'api_provider'
        ]
    
    def get_token_cost(self, obj):
        """Calculate cost per token"""
        if obj.total_tokens > 0:
            return float(obj.estimated_user_cost) / obj.total_tokens
        return 0
    
    def get_your_profit(self, obj):
        """Get YOUR profit from this request"""
        return float(obj.your_service_fee)
    
    def get_is_free(self, obj):
        """Check if this request was FREE (using Groq)"""
        return obj.is_free
    
    def create(self, validated_data):
        # Automatically set the user to the current user
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    monthly_price_display = serializers.SerializerMethodField()
    popular = serializers.SerializerMethodField()
    your_profit_margin = serializers.SerializerMethodField()
    
    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'tier', 'monthly_price', 'monthly_price_display',
            'description', 'features', 'stripe_price_id',
            'suggested_daily_requests', 'suggested_monthly_tokens',
            'includes_pdf_analysis', 'includes_data_analysis',
            'your_cost_per_user', 'your_profit_per_user', 'your_profit_margin',
            'popular'
        ]
        read_only_fields = ['stripe_price_id']
    
    def get_monthly_price_display(self, obj):
        if obj.monthly_price == 0:
            return "Free"
        return f"${obj.monthly_price:.2f}/month"
    
    def get_popular(self, obj):
        # Mark Premium as popular
        return obj.tier == 'premium'
    
    def get_your_profit_margin(self, obj):
        return f"{obj.your_profit_margin}%"

class APIProxyLogSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    timestamp_display = serializers.SerializerMethodField()
    cost_display = serializers.SerializerMethodField()
    your_profit_display = serializers.SerializerMethodField()
    is_free = serializers.SerializerMethodField()
    
    class Meta:
        model = APIProxyLog
        fields = [
            'id', 'user', 'username', 'timestamp', 'timestamp_display',
            'endpoint', 'model', 'input_tokens', 'output_tokens',
            'total_tokens', 'estimated_user_cost', 'cost_display',
            'your_service_fee', 'your_profit_display', 'response_time_ms',
            'success', 'error_message', 'provider', 'request_type', 'is_free'
        ]
        read_only_fields = ['timestamp']
    
    def get_timestamp_display(self, obj):
        return obj.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    def get_cost_display(self, obj):
        return f"${obj.estimated_user_cost:.6f}"
    
    def get_your_profit_display(self, obj):
        return f"${obj.your_service_fee:.6f}"
    
    def get_is_free(self, obj):
        return obj.is_free

class RateLimitLogSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    timestamp_display = serializers.SerializerMethodField()
    
    class Meta:
        model = RateLimitLog
        fields = [
            'id', 'user', 'username', 'timestamp', 'timestamp_display',
            'limit_type', 'limit_value', 'current_usage', 'request_path'
        ]
        read_only_fields = ['timestamp']
    
    def get_timestamp_display(self, obj):
        return obj.timestamp.strftime('%Y-%m-%d %H:%M:%S')

class BillingTransactionSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    plan_name = serializers.CharField(source='plan.name', read_only=True)
    timestamp_display = serializers.SerializerMethodField()
    your_profit_display = serializers.SerializerMethodField()
    
    class Meta:
        model = BillingTransaction
        fields = [
            'id', 'user', 'username', 'timestamp', 'timestamp_display',
            'amount', 'currency', 'plan', 'plan_name', 'period_start',
            'period_end', 'stripe_fee', 'hosting_fee', 
            'stripe_payment_intent_id', 'stripe_invoice_id',
            'stripe_invoice_url', 'status', 'your_profit', 'profit_margin',
            'your_profit_display'
        ]
        read_only_fields = ['timestamp']
    
    def get_timestamp_display(self, obj):
        return obj.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    def get_your_profit_display(self, obj):
        return f"${obj.your_profit:.2f}"

class APIAutoSetupRequestSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    requested_at_display = serializers.SerializerMethodField()
    completed_at_display = serializers.SerializerMethodField()
    is_free = serializers.SerializerMethodField()
    
    class Meta:
        model = APIAutoSetupRequest
        fields = [
            'id', 'user', 'username', 'provider', 'requested_at',
            'requested_at_display', 'completed_at', 'completed_at_display',
            'status', 'api_key', 'account_email', 'account_id',
            'error_message', 'error_code', 'setup_instructions',
            'is_completed', 'took_seconds', 'is_free', 'free_tokens_info'
        ]
        read_only_fields = ['requested_at']
    
    def get_requested_at_display(self, obj):
        return obj.requested_at.strftime('%Y-%m-%d %H:%M:%S')
    
    def get_completed_at_display(self, obj):
        if obj.completed_at:
            return obj.completed_at.strftime('%Y-%m-%d %H:%M:%S')
        return None
    
    def get_is_free(self, obj):
        return obj.is_free

class ProfitAnalyticsSerializer(serializers.ModelSerializer):
    date_display = serializers.SerializerMethodField()
    profit_margin_display = serializers.SerializerMethodField()
    
    class Meta:
        model = ProfitAnalytics
        fields = [
            'id', 'date', 'date_display', 'total_revenue', 'stripe_fees',
            'hosting_costs', 'active_free_users', 'active_premium_users',
            'active_unlimited_users', 'total_requests', 'total_tokens_proxied',
            'total_your_service_fees', 'groq_requests', 'free_tokens_used',
            'total_reseller_commissions', 'total_reseller_payouts',
            'total_costs', 'net_profit', 'profit_margin', 'profit_margin_display', 
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
    def get_date_display(self, obj):
        return obj.date.strftime('%Y-%m-%d')
    
    def get_profit_margin_display(self, obj):
        return f"{obj.profit_margin:.1f}%"

class UserSubscriptionSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    plan_name = serializers.CharField(source='plan.name', read_only=True)
    your_profit_info = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSubscription
        fields = [
            'id', 'user', 'username', 'plan', 'plan_name', 'status',
            'stripe_subscription_id', 'stripe_customer_id',
            'current_period_start', 'current_period_end', 'canceled_at',
            'trial_start', 'trial_end', 'created_at', 'updated_at',
            'is_active', 'your_profit_info'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
def get_your_profit_info(self, obj):
    return obj.get_your_profit()  # Calls the correct method name from your UserProfile model

# === RESELLER SERIALIZERS ===

class ResellerSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.EmailField(source='user.email', read_only=True)
    stats = serializers.SerializerMethodField()
    total_earnings = serializers.SerializerMethodField()
    available_balance = serializers.SerializerMethodField()
    total_clients = serializers.SerializerMethodField()
    active_clients = serializers.SerializerMethodField()
    signup_url = serializers.SerializerMethodField()
    
    class Meta:
        model = Reseller
        fields = [
            'id', 'user', 'username', 'user_email', 'name', 'company', 'website',
            'description', 'code', 'default_commission_rate', 'discount_percent',
            'signup_bonus', 'status', 'is_active', 'approved_by', 'approved_at',
            'created_at', 'updated_at', 'stats', 'total_earnings', 'available_balance',
            'total_clients', 'active_clients', 'signup_url'
        ]
        read_only_fields = [
            'code', 'created_at', 'updated_at', 'approved_by', 'approved_at'
        ]
    
    def get_stats(self, obj):
        return obj.calculate_stats()
    
    def get_total_earnings(self, obj):
        stats = obj.calculate_stats()
        return float(stats['total_earnings'])
    
    def get_available_balance(self, obj):
        stats = obj.calculate_stats()
        return float(stats['available_balance'])
    
    def get_total_clients(self, obj):
        return obj.resellerclient_set.count()
    
    def get_active_clients(self, obj):
        return obj.resellerclient_set.filter(status='active').count()
    
    def get_signup_url(self, obj):
        return f"/register?reseller_code={obj.code}"
    
    def validate_default_commission_rate(self, value):
        if value < 0 or value > 0.5:  # Max 50% commission
            raise serializers.ValidationError("Commission rate must be between 0 and 0.5 (50%)")
        return value
    
    def validate_discount_percent(self, value):
        if value < 0 or value > 50:  # Max 50% discount
            raise serializers.ValidationError("Discount percentage must be between 0 and 50")
        return value

class ResellerClientSerializer(serializers.ModelSerializer):
    reseller_name = serializers.CharField(source='reseller.name', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.EmailField(source='user.email', read_only=True)
    total_commission = serializers.SerializerMethodField()
    subscription_tier = serializers.SerializerMethodField()
    subscription_status = serializers.SerializerMethodField()
    
    class Meta:
        model = ResellerClient
        fields = [
            'id', 'reseller', 'reseller_name', 'user', 'username', 'user_email',
            'commission_rate', 'status', 'created_at', 'updated_at',
            'total_commission', 'subscription_tier', 'subscription_status'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
    def get_total_commission(self, obj):
        return float(obj.calculate_total_commission())
    
    def get_subscription_tier(self, obj):
        try:
            return obj.user.userprofile.subscription_tier
        except:
            return 'free'
    
    def get_subscription_status(self, obj):
        try:
            return obj.user.userprofile.subscription_status
        except:
            return 'inactive'

class ResellerCommissionSerializer(serializers.ModelSerializer):
    reseller_name = serializers.CharField(source='reseller.name', read_only=True)
    client_username = serializers.SerializerMethodField()
    transaction_type_display = serializers.SerializerMethodField()
    timestamp_display = serializers.SerializerMethodField()
    commission_rate_percent = serializers.SerializerMethodField()
    
    class Meta:
        model = ResellerCommission
        fields = [
            'id', 'reseller', 'reseller_name', 'client', 'client_username',
            'transaction_type', 'transaction_type_display', 'transaction',
            'subscription_transaction', 'commission_rate', 'commission_rate_percent',
            'commission_amount', 'payout', 'status', 'notes', 'created_at',
            'updated_at', 'timestamp_display'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
    def get_client_username(self, obj):
        if obj.client and obj.client.user:
            return obj.client.user.username
        return None
    
    def get_transaction_type_display(self, obj):
        return dict(obj.TRANSACTION_TYPES).get(obj.transaction_type, obj.transaction_type)
    
    def get_timestamp_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')
    
    def get_commission_rate_percent(self, obj):
        return f"{float(obj.commission_rate * 100)}%"

class ResellerPayoutSerializer(serializers.ModelSerializer):
    reseller_name = serializers.CharField(source='reseller.name', read_only=True)
    reseller_code = serializers.CharField(source='reseller.code', read_only=True)
    timestamp_display = serializers.SerializerMethodField()
    processed_at_display = serializers.SerializerMethodField()
    payout_method_display = serializers.SerializerMethodField()
    
    class Meta:
        model = ResellerPayout
        fields = [
            'id', 'reseller', 'reseller_name', 'reseller_code', 'amount',
            'payout_method', 'payout_method_display', 'payment_reference',
            'transaction_id', 'status', 'notes', 'processed_by', 'processed_at',
            'processed_at_display', 'created_at', 'updated_at', 'timestamp_display'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
    def get_timestamp_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')
    
    def get_processed_at_display(self, obj):
        if obj.processed_at:
            return obj.processed_at.strftime('%Y-%m-%d %H:%M:%S')
        return None
    
    def get_payout_method_display(self, obj):
        return dict(obj.PAYOUT_METHODS).get(obj.payout_method, obj.payout_method)

# Simplified serializers for basic operations
class SimpleUserProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'id', 'username', 'subscription_tier', 'subscription_status',
            'requests_today', 'has_api_key', 'preferred_provider'
        ]

class UsageStatsSerializer(serializers.Serializer):
    """Serializer for usage statistics endpoint"""
    tier = serializers.CharField()
    requests_today = serializers.IntegerField()
    daily_limit = serializers.IntegerField()
    usage_percentage = serializers.FloatField()
    tokens_this_month = serializers.IntegerField()
    has_api_key = serializers.BooleanField()
    subscription_active = serializers.BooleanField()
    subscription_tier = serializers.CharField()
    your_profit_info = serializers.DictField()
    reseller_info = serializers.DictField(required=False)

class CheckLimitSerializer(serializers.Serializer):
    """Serializer for rate limit check endpoint"""
    can_send = serializers.BooleanField()
    message = serializers.CharField()
    requests_today = serializers.IntegerField()
    daily_limit = serializers.IntegerField()
    usage_percentage = serializers.FloatField()
    messages_remaining = serializers.IntegerField()
    tier = serializers.CharField()

class ApiKeySetupSerializer(serializers.Serializer):
    """Serializer for API key setup"""
    provider = serializers.ChoiceField(choices=['groq', 'openai', 'anthropic', 'gemini'])
    api_key = serializers.CharField(max_length=255)

class AutoSetupRequestSerializer(serializers.Serializer):
    """Serializer for auto API setup request"""
    provider = serializers.ChoiceField(choices=['groq', 'openai', 'anthropic', 'gemini'])

class CheckoutSerializer(serializers.Serializer):
    """Serializer for checkout session creation"""
    plan_tier = serializers.ChoiceField(choices=['premium', 'unlimited'])
    reseller_code = serializers.CharField(required=False, allow_blank=True)

class PDFAnalysisSerializer(serializers.Serializer):
    """Serializer for PDF analysis request"""
    file = serializers.FileField()
    question = serializers.CharField(required=False, allow_blank=True)

class ResellerApplicationSerializer(serializers.Serializer):
    """Serializer for reseller application"""
    name = serializers.CharField(max_length=100)
    company = serializers.CharField(required=False, allow_blank=True, max_length=100)
    website = serializers.URLField(required=False, allow_blank=True)
    description = serializers.CharField(required=False, allow_blank=True)
    commission_rate = serializers.DecimalField(max_digits=5, decimal_places=2, min_value=0, max_value=0.5, default=0.3)

class ResellerPayoutRequestSerializer(serializers.Serializer):
    """Serializer for reseller payout request"""
    payout_method = serializers.ChoiceField(choices=['stripe', 'paypal', 'bank_transfer', 'crypto'], default='stripe')
    amount = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=10.0)  # Min $10