# api/urls.py - CORRECTED VERSION

from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView
from .health import health_check

urlpatterns = [
    # === HEALTH CHECK ===
    path('health/', health_check, name='health_check'),
    
    # === USER AUTHENTICATION (SIMPLE ENDPOINTS) ===
    path('register/', views.register, name='register'),  # Frontend calls this
    path('login/', views.login_user, name='login'),  # Frontend calls this
    path('logout/', views.logout_user, name='logout'),
    path('refresh-token/', views.refresh_token, name='token_refresh'),
    path('current-user/', views.get_current_user, name='current_user'),
    
    # === USER PROFILE ===
    path('profile/', views.my_profile, name='my_profile'),
    
    # === DOCUMENT UPLOAD & ANALYSIS ===
    path('upload-document/', views.upload_document, name='upload_document'),
    path('documents/', views.get_user_documents, name='get_user_documents'),
    path('documents/<int:document_id>/delete/', views.delete_document, name='delete_document'),
    path('analyze-document/', views.analyze_document, name='analyze_document'),
    path('check-pdf-limits/', views.check_pdf_limits, name='check_pdf_limits'),
    path('reset-pdf-counter/', views.reset_pdf_counter, name='reset_pdf_counter'),
    
    # === AI CHAT ===
    path('ai-chat/', views.ai_study_helper, name='ai_study_helper'),
    path('conversations/', views.AIConversationList.as_view(), name='ai_conversations'),
    path('clear-memory/', views.clear_ai_memory, name='clear_ai_memory'),
    path('batch-questions/', views.batch_ai_questions, name='batch_ai_questions'),
    
    # === API KEY MANAGEMENT ===
    path('set-api-key/', views.set_api_key, name='set_api_key'),
    path('auto-setup/', views.request_auto_api_setup, name='auto_api_setup'),
    path('groq-auto-setup/', views.request_groq_auto_setup, name='groq_auto_setup'),
    path('test-openai-key/', views.test_openai_key, name='test_openai_key'),
    
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
    path('admin/reset-daily/', views.reset_daily_counters, name='reset_daily'),
    path('admin/reset-monthly/', views.reset_monthly_counters, name='reset_monthly'),
    path('admin/setup-initial/', views.setup_initial_data, name='setup_initial'),
    path('admin/resellers/', views.admin_reseller_list, name='admin_reseller_list'),
    path('admin/resellers/<int:reseller_id>/approve/', views.admin_approve_reseller, name='admin_approve_reseller'),
    path('admin/reset-pdf-limit/<int:user_id>/', views.admin_reset_pdf_limit, name='admin_reset_pdf_limit'),
    
    # === TEST ENDPOINTS (for debugging) ===
    path('test-upload/', views.test_upload, name='test_upload'),
    path('debug-users/', views.debug_users, name='debug_users'),
]