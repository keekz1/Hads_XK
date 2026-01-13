# api/urls.py - CORRECTED

from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView
from .health import health_check

urlpatterns = [
    # === USER AUTHENTICATION ===
    path('register/', views.register, name='register'),
    path('profile/', views.my_profile, name='my_profile'),
    path('login/', TokenObtainPairView.as_view(), name='login'),
  # Document upload endpoints
    path('upload-document/', views.upload_document, name='upload_document'),
    path('documents/', views.get_user_documents, name='get_user_documents'),
    path('documents/<int:document_id>/delete/', views.delete_document, name='delete_document'),
path('analyze-document/', views.analyze_document, name='analyze_document'),  # Add this line
         path('health/', health_check, name='health_check'),

    # === AI CHAT ===
    path('ai-chat/', views.ai_study_helper, name='ai_study_helper'),
    path('conversations/', views.AIConversationList.as_view(), name='ai_conversations'),
    path('clear-memory/', views.clear_ai_memory, name='clear_ai_memory'),
    path('batch-questions/', views.batch_ai_questions, name='batch_ai_questions'),
    
    # === API KEY MANAGEMENT ===
    path('set-api-key/', views.set_api_key, name='set_api_key'),
    path('auto-setup/', views.request_auto_api_setup, name='auto_api_setup'),
    path('groq-auto-setup/', views.request_groq_auto_setup, name='groq_auto_setup'),
    
    # === PDF ANALYSIS ===
    path('analyze-pdf/', views.analyze_pdf, name='analyze_pdf'),
    
    # === BILLING & SUBSCRIPTION ===
    path('plans/', views.get_subscription_plans, name='get_plans'),
    path('create-checkout/', views.create_checkout_session, name='create_checkout'),
    path('cancel-subscription/', views.cancel_subscription, name='cancel_subscription'),
    path('stripe-webhook/', views.stripe_webhook, name='stripe_webhook'),
    
    # === USAGE & ANALYTICS ===
    path('usage-stats/', views.get_usage_stats, name='usage_stats'),
    path('check-rate-limit/', views.check_rate_limit, name='check_rate_limit'),
    path('your-profit-dashboard/', views.get_your_profit_dashboard, name='profit_dashboard'),
    
    # === RESELLER ENDPOINTS ===
    path('apply-reseller/', views.apply_reseller, name='apply_reseller'),
    path('reseller-dashboard/', views.get_reseller_dashboard, name='reseller_dashboard'),
    path('request-payout/', views.request_reseller_payout, name='request_payout'),
    path('reseller/<str:code>/', views.get_reseller_info, name='reseller_info'),
    
    # === ADMIN ENDPOINTS ===
    path('admin/reset-daily/', views.reset_daily_counters, name='reset_daily'),  # FIXED: plural
    path('admin/reset-monthly/', views.reset_monthly_counters, name='reset_monthly'),
    path('admin/setup-initial/', views.setup_initial_data, name='setup_initial'),
    path('admin/resellers/', views.admin_reseller_list, name='admin_reseller_list'),
    path('admin/resellers/<int:reseller_id>/approve/', views.admin_approve_reseller, name='admin_approve_reseller'),
]