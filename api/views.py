# Django core imports
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.db import models
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.files.storage import default_storage
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt  # ADD THIS
from django.http import JsonResponse  # ADD THIS
import logging
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .ai import proxy_ai_request_with_images, analyze_document_with_ai ,  generate_image_with_replicate_ap
# Django REST Framework imports
from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions, filters, generics
from rest_framework.filters import SearchFilter
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

# Third-party imports
from django_filters.rest_framework import DjangoFilterBackend
from decimal import Decimal
import PyPDF2
import docx
import replicate

# Standard library imports
import os
import time
import json
import uuid
import traceback
import requests

# Local imports
from .models import (
    UserProfile, StudyContent, AIConversation, 
    SubscriptionPlan, UserSubscription, BillingTransaction,
    APIProxyLog, APIAutoSetupRequest, ProfitAnalytics,
    Reseller, ResellerClient, ResellerCommission, ResellerPayout,
    UploadedDocument
)
from .serializers import (
    UserProfileSerializer, StudyContentSerializer, 
    AIConversationSerializer, ResellerSerializer,
    UploadedDocumentSerializer
)
from .ai import proxy_ai_request_with_images, analyze_document_with_ai  # ADD THIS

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')
    level = request.data.get('level', 'beginner')
    reseller_code = request.data.get('reseller_code', None)
    referred_by = request.data.get('referred_by', None)

    print(f"=== REGISTER REQUEST ===")
    print(f"Username: {username}")
    print(f"Email: {email}")
    print(f"Password length: {len(password) if password else 0}")

    if not username or not password:
        print("ERROR: Missing username or password")
        return Response({"error": "Username and password required"}, status=400)

    # Check if user exists (case-insensitive)
    if User.objects.filter(username__iexact=username).exists():
        print(f"ERROR: Username '{username}' already exists")
        return Response({"error": "Username already exists"}, status=400)

    if email and User.objects.filter(email__iexact=email).exists():
        print(f"ERROR: Email '{email}' already exists")
        return Response({"error": "Email already exists"}, status=400)

    try:
        with transaction.atomic():
            # Create user with proper password hashing
            print(f"Creating user '{username}'...")
            user = User.objects.create_user(
                username=username,
                password=password,
                email=email if email else None,
                is_active=True
            )
            
            print(f"User created with ID: {user.id}")

            # Get or create profile
            profile, created = UserProfile.objects.get_or_create(
                user=user,
                defaults={
                    'level': level,
                    'referred_by_code': referred_by
                }
            )
            
            if not created:
                profile.level = level
                profile.referred_by_code = referred_by
                profile.save()
            
            print(f"Profile created/updated: {profile.id}")

            # Handle reseller signup if reseller_code provided
            if reseller_code:
                try:
                    reseller = Reseller.objects.get(code=reseller_code, is_active=True)
                    ResellerClient.objects.create(
                        reseller=reseller,
                        user=user,
                        commission_rate=reseller.default_commission_rate,
                        status='active'
                    )
                    profile.reseller_code_used = reseller_code
                    profile.save()
                    print(f"User enrolled with reseller: {reseller_code}")
                except Reseller.DoesNotExist:
                    print(f"Reseller code '{reseller_code}' not found, skipping...")
            
            # **REMOVED: DO NOT generate JWT tokens here**
            # This is the key change - no tokens on registration
            
            # **ADD: Simple verification that user was created**
            print(f"Testing authentication for verification...")
            test_auth = authenticate(username=username, password=password)
            print(f"Verification result: {'SUCCESS' if test_auth else 'FAILED'}")

            response_data = {
                "success": True,
                "message": "User created successfully. Please log in.",
                "username": user.username,
                "email": user.email,
                "tier": "free",
                "daily_requests_limit": profile.get_tier_limits()['daily_requests'],
                "requires_api_key": True,
                "setup_steps": [
                    "1. Subscribe to a paid plan for higher limits",
                    "2. Set up your Groq/OpenAI/Anthropic API key",
                    "3. Start using AI study assistance"
                ],
                "reseller_enrolled": bool(reseller_code),
                # **REMOVED: 'tokens' field**
                # **ADD: user info without sensitive data**
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "date_joined": user.date_joined.strftime('%Y-%m-%dT%H:%M:%SZ')
                },
                # **ADD: Instructions for next step**
                "next_steps": {
                    "login_url": "/api/login/",
                    "message": "Registration successful! Please log in with your credentials."
                }
            }
            
            print(f"Registration successful! User created but NOT logged in.")
            return Response(response_data, status=201)
            
    except Exception as e:
        import traceback
        print(f"=== REGISTRATION EXCEPTION ===")
        print(f"Error: {str(e)}")
        traceback.print_exc()
        return Response({
            "error": f"Registration failed: {str(e)}",
            "details": str(e)
        }, status=400)
    
@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    """Login user and return JWT tokens"""
    print("=== LOGIN VIEW CALLED ===")
    print(f"Request data: {request.data}")
    
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        print("ERROR: Missing username or password")
        return Response(
            {'error': 'Username and password are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    print(f"Attempting authentication for user: {username}")
    
    # First, check if user exists
    try:
        user = User.objects.get(username=username)
        print(f"User found: ID={user.id}, Active={user.is_active}")
        
        # Manual password check for debugging
        if user.check_password(password):
            print("✅ Password check PASSED")
        else:
            print("❌ Password check FAILED")
            print(f"Stored hash: {user.password[:50]}...")
            
    except User.DoesNotExist:
        # Try case-insensitive lookup
        try:
            user = User.objects.get(username__iexact=username)
            print(f"User found with case-insensitive lookup: {user.username}")
        except User.DoesNotExist:
            print(f"❌ User '{username}' not found")
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )
    
    # Authenticate with Django's auth system
    user = authenticate(username=username, password=password)
    
    if user is not None:
        print(f"✅ Django authentication SUCCESSFUL for: {user.username}")
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        print(f"Generated access token: {str(refresh.access_token)[:20]}...")
        
        # Get or create user profile
        profile, created = UserProfile.objects.get_or_create(
            user=user,
            defaults={'level': 'beginner'}
        )
        
        if created:
            print(f"Created new profile for user")
        
        return Response({
            "success": True,
            "message": "Login successful",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "date_joined": user.date_joined.strftime('%Y-%m-%dT%H:%M:%SZ')
            },
            "profile": {
                "level": profile.level,
                "subscription_tier": profile.subscription_tier,
                "has_api_key": profile.has_api_key()
            },
            "tokens": {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
        })
    else:
        print(f"❌ Authentication FAILED for user: {username}")
        
        # More detailed error messages
        try:
            user = User.objects.get(username=username)
            if not user.is_active:
                error_msg = "Account is disabled"
            elif not user.check_password(password):
                error_msg = "Invalid password"
            else:
                error_msg = "Authentication failed"
        except User.DoesNotExist:
            error_msg = "User does not exist"
        
        return Response(
            {"error": error_msg},
            status=status.HTTP_401_UNAUTHORIZED
        )
        
        
@csrf_exempt
def generate_image(request):
    """Legacy image generation endpoint (for backward compatibility)"""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            prompt = data.get("prompt", "")
            
            # Get token from settings
            api_token = getattr(settings, 'REPLICATE_API_TOKEN', None)
            
            if not api_token:
                return JsonResponse({
                    "success": False,
                    "error": "Replicate API token not configured"
                }, status=500)
            
            # Call Replicate
            output = replicate.run(
                "stability-ai/sdxl:39ed52f2a78e934b3ba6e2a89f5b1c712de7dfea535525255b1aa35c5565e08b",
                input={"prompt": prompt},
                api_token=api_token
            )
            
            return JsonResponse({
                "success": True,
                "image_url": output[0] if isinstance(output, list) else output
            })
            
        except Exception as e:
            return JsonResponse({
                "success": False,
                "error": str(e)
            }, status=500)
    
    return JsonResponse({"error": "Method not allowed"}, status=405)
        
        
@api_view(['POST'])
@authentication_classes([JWTAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def analyze_document(request):
    """Analyze an uploaded document with AI using enhanced function"""
    print(f"Analyze document called by user: {request.user.username}")
    
    try:
        document_id = request.data.get('document_id')
        question = request.data.get('question', '')
        
        if not document_id:
            print("ERROR: No document_id provided")
            return Response(
                {'error': 'Document ID required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get document
        try:
            document = UploadedDocument.objects.get(id=document_id, user=request.user)
            print(f"Found document: {document.file_name}")
        except UploadedDocument.DoesNotExist:
            print(f"ERROR: Document {document_id} not found for user {request.user.username}")
            return Response(
                {'error': 'Document not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if not document.extracted_text:
            print(f"ERROR: Document {document_id} has no extracted text")
            return Response(
                {'error': 'Document has no extracted text'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get user profile
        profile = request.user.userprofile
        
        # Use the enhanced analyze_document_with_ai function
        result = analyze_document_with_ai(
            document_text=document.extracted_text,
            question=question if question else "",
            api_key=profile.get_api_key(),
            provider=profile.preferred_provider,
            model=profile.preferred_model,
            user_profile=profile
        )
        
        if result.get("success"):
            # Update PDF analysis count
            profile.pdf_analyses_this_month += 1
            profile.save()
            
            # Save the analysis conversation
            conversation = AIConversation.objects.create(
                user=request.user,
                prompt=f"Document analysis: {document.file_name}\n\nQuestion: {question}" if question else f"Document analysis: {document.file_name}",
                response=result["analysis"],
                subject="Document Analysis",
                difficulty="advanced",
                user_tier_at_time=profile.subscription_tier,
                model_used=result.get("model", profile.preferred_model),
                input_tokens=result.get("input_tokens", 0),
                output_tokens=result.get("output_tokens", 0),
                total_tokens=result.get("tokens_used", 0),
                estimated_user_cost=Decimal('0.00'),
                your_service_fee=Decimal('0.0001'),
                api_provider=result.get("provider", profile.preferred_provider),
                response_time_ms=0,
                is_document_analysis=True,
                document_analyzed=document
            )
            
            # Log the proxy request
            api_log = APIProxyLog.objects.create(
                user=request.user,
                endpoint="document_analysis",
                model=result.get("model", profile.preferred_model),
                input_tokens=result.get("input_tokens", 0),
                output_tokens=result.get("output_tokens", 0),
                total_tokens=result.get("tokens_used", 0),
                estimated_user_cost=Decimal('0.00'),
                your_service_fee=Decimal('0.0001'),
                response_time_ms=0,
                success=True,
                provider=result.get("provider", profile.preferred_provider),
                request_type="document_analysis",
                key_source="user" if not result.get("using_system_fallback") else "system_fallback"
            )
            
            return Response({
                "success": True,
                "analysis": result["analysis"],
                "summary": {
                    "document_name": document.file_name,
                    "question": question if question else "General analysis",
                    "tokens_used": result.get("tokens_used", 0),
                    "provider": result.get("provider", profile.preferred_provider),
                    "model": result.get("model", profile.preferred_model),
                    "using_system_key": result.get("using_system_fallback", False),
                    "pdf_analyses_used": profile.pdf_analyses_this_month,
                    "pdf_analyses_limit": profile.get_tier_limits().get('pdf_limit', 0)
                },
                "conversation_id": conversation.id,
                "document": {
                    "id": document.id,
                    "name": document.file_name,
                    "type": document.file_type,
                    "pages": document.page_count,
                    "size_mb": round(document.file_size / (1024 * 1024), 2)
                }
            })
        else:
            return Response({
                "success": False,
                "error": result.get("error", "Analysis failed"),
                "requires_setup": result.get("requires_setup", False),
                "suggestion": result.get("suggestion", "")
            }, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        import traceback
        error_msg = f"Document analysis error: {str(e)}"
        print(error_msg)
        traceback.print_exc()
        return Response(
            {'error': f'Analysis failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        
@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token(request):
    """Refresh JWT token"""
    refresh_token = request.data.get('refresh')
    
    if not refresh_token:
        return Response(
            {"error": "Refresh token is required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        refresh = RefreshToken(refresh_token)
        user_id = refresh['user_id']
        user = User.objects.get(id=user_id)
        
        # Generate new access token
        new_access_token = str(refresh.access_token)
        
        return Response({
            "success": True,
            "access": new_access_token
        })
        
    except Exception as e:
        return Response(
            {"error": "Invalid refresh token"},
            status=status.HTTP_401_UNAUTHORIZED
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    """Logout user (blacklist token)"""
    try:
        refresh_token = request.data.get("refresh")
        token = RefreshToken(refresh_token)
        token.blacklist()
        
        return Response({
            "success": True,
            "message": "Successfully logged out"
        })
    except Exception as e:
        return Response({
            "success": False,
            "error": str(e)
        }, status=400)        
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_user(request):
    """Get current authenticated user's profile"""
    user = request.user
    
    try:
        profile = user.userprofile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=user, level="beginner")
    
    # Get usage statistics
    tier_limits = profile.get_tier_limits()
    
    return Response({
        "success": True,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "date_joined": user.date_joined,
            "is_staff": user.is_staff,
            "is_superuser": user.is_superuser
        },
        "profile": {
            "level": profile.level,
            "subscription_tier": profile.subscription_tier,
            "subscription_status": profile.subscription_status,
            "preferred_provider": profile.preferred_provider,
            "preferred_model": profile.preferred_model,
            "has_api_key": profile.has_api_key(),
            "api_provider_info": profile.get_provider_info()
        },
        "usage": {
            "requests_today": profile.requests_today,
            "daily_limit": tier_limits['daily_requests'],
            "tokens_this_month": profile.tokens_this_month,
            "pdf_analyses_this_month": profile.pdf_analyses_this_month,
            "data_analyses_this_month": profile.data_analyses_this_month,
            "monthly_reset_date": profile.monthly_reset_date
        }
    })    

# Add this simple test endpoint first
@csrf_exempt
def test_upload(request):
    """Test endpoint to verify upload works without auth"""
    print("=== TEST UPLOAD CALLED ===")
    print("Method:", request.method)
    print("Content-Type:", request.content_type)
    print("User:", request.user)
    print("Files:", dict(request.FILES))
    
    if request.method == 'POST':
        if 'file' in request.FILES:
            file = request.FILES['file']
            return JsonResponse({
                'success': True,
                'filename': file.name,
                'size': file.size,
                'message': 'Test endpoint works!'
            })
        return JsonResponse({'error': 'No file provided'}, status=400)
    
    return JsonResponse({'error': 'Use POST method'}, status=400)

@api_view(['POST'])
@authentication_classes([JWTAuthentication, SessionAuthentication])  # Use JWT + Session
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def upload_document(request):
    """Handle document uploads"""
    print("=== UPLOAD DOCUMENT VIEW CALLED ===")
    print(f"User: {request.user.username}")
    print(f"Authenticated: {request.user.is_authenticated}")
    print(f"Auth header: {request.headers.get('Authorization')}")
    print(f"Files in request: {dict(request.FILES)}")
    
    try:
        if 'file' not in request.FILES:
            print("ERROR: No file in request.FILES")
            return Response(
                {'error': 'No file provided'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        uploaded_file = request.FILES['file']
        file_name = uploaded_file.name
        print(f"Processing file: {file_name}, Size: {uploaded_file.size}")
        
        # Check file size (max 50MB)
        max_size = 50 * 1024 * 1024  # 50MB
        if uploaded_file.size > max_size:
            print(f"ERROR: File too large: {uploaded_file.size} bytes")
            return Response(
                {'error': f'File too large. Maximum size is 50MB. Your file is {uploaded_file.size / (1024*1024):.2f}MB'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check file type
        allowed_extensions = ['.pdf', '.docx', '.txt', '.doc', '.jpg', '.jpeg', '.png', 
                             '.xlsx', '.xls', '.csv', '.ppt', '.pptx']
        ext = os.path.splitext(file_name)[1].lower()
        
        if ext not in allowed_extensions:
            print(f"ERROR: Invalid file type: {ext}")
            return Response(
                {'error': f'File type not allowed. Allowed types: {", ".join(allowed_extensions)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check user's PDF analysis limit - ADD ERROR HANDLING HERE
        profile = request.user.userprofile
        
        # TEMPORARY FIX: Wrap this in try-except
        try:
            tier_limits = profile.get_tier_limits()
            
            if profile.pdf_analyses_this_month >= tier_limits.get('pdf_limit', 0):
                print(f"ERROR: PDF limit reached: {profile.pdf_analyses_this_month}/{tier_limits.get('pdf_limit', 0)}")
                return Response({
                    'error': 'PDF analysis limit reached',
                    'limit': tier_limits.get('pdf_limit', 0),
                    'used': profile.pdf_analyses_this_month,
                    'upgrade_url': '/plans/'
                }, status=status.HTTP_402_PAYMENT_REQUIRED)
        
        except AttributeError as e:
            print(f"WARNING: get_tier_limits() not found: {e}")
            # Use default limits temporarily
            tier_limits = {'pdf_limit': 3, 'can_analyze_pdf': True}
        
         
        if profile.pdf_analyses_this_month >= tier_limits.get('pdf_limit', 0):
            print(f"ERROR: PDF limit reached: {profile.pdf_analyses_this_month}/{tier_limits.get('pdf_limit', 0)}")
            return Response({
                'error': 'PDF analysis limit reached',
                'limit': tier_limits.get('pdf_limit', 0),
                'used': profile.pdf_analyses_this_month,
                'upgrade_url': '/plans/'
            }, status=status.HTTP_402_PAYMENT_REQUIRED)
        
        print(f"Creating document record for user: {request.user.username}")
        
        # Create document record
        document = UploadedDocument.objects.create(
            user=request.user,
            file=uploaded_file,
            file_name=file_name
        )
        
        # Determine file type
        if ext == '.pdf':
            document.file_type = 'pdf'
        elif ext in ['.docx', '.doc']:
            document.file_type = 'docx'
        elif ext == '.txt':
            document.file_type = 'txt'
        elif ext in ['.jpg', '.jpeg', '.png', '.gif']:
            document.file_type = 'image'
        elif ext in ['.xlsx', '.xls', '.csv']:
            document.file_type = 'excel'
        elif ext in ['.ppt', '.pptx']:
            document.file_type = 'ppt'
        
        document.file_size = uploaded_file.size
        document.save()
        
        print(f"Document created: ID {document.id}, Type: {document.file_type}")
        
        # Extract text (simplified version)
        try:
            if document.file_type == 'pdf':
                print("Extracting text from PDF...")
                pdf_reader = PyPDF2.PdfReader(document.file)
                document.page_count = len(pdf_reader.pages)
                text = ""
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n\n"
                document.extracted_text = text[:100000]  # Limit to 100k chars
                print(f"PDF extracted: {document.page_count} pages, {len(text)} chars")
            elif document.file_type == 'docx':
                print("Extracting text from DOCX...")
                doc = docx.Document(document.file)
                document.page_count = 1
                text = ""
                for para in doc.paragraphs:
                    text += para.text + "\n"
                document.extracted_text = text[:100000]
                print(f"DOCX extracted: {len(text)} chars")
            elif document.file_type == 'txt':
                print("Extracting text from TXT...")
                document.file.seek(0)
                text = document.file.read().decode('utf-8', errors='ignore')
                document.page_count = 1
                document.extracted_text = text[:100000]
                print(f"TXT extracted: {len(text)} chars")
            else:
                document.extracted_text = f"[{document.file_type.upper()} file: {file_name}]"
                document.page_count = 1
                print(f"Other file type: {document.file_type}")
        except Exception as e:
            print(f"ERROR extracting text: {str(e)}")
            document.extracted_text = f"Error extracting text: {str(e)}"
        
        document.is_processed = True
        document.save()
        
        # Update user's PDF analysis count
        profile.pdf_analyses_this_month += 1
        profile.save()
        
        print(f"Upload successful! Document ID: {document.id}")
        
        return Response({
            'success': True,
            'message': f'File "{file_name}" uploaded successfully',
            'document': {
                'id': document.id,
                'file_name': document.file_name,
                'file_type': document.file_type,
                'file_size': document.file_size,
                'file_size_mb': round(document.file_size / (1024 * 1024), 2),
                'uploaded_at': document.uploaded_at.isoformat(),
                'page_count': document.page_count,
                'is_processed': document.is_processed,
                'preview': document.extracted_text[:500] + "..." if document.extracted_text and len(document.extracted_text) > 500 else document.extracted_text
            },
            'analysis_count': profile.pdf_analyses_this_month,
            'analysis_limit': tier_limits.get('pdf_limit', 0)
        })
        
    except Exception as e:
        import traceback
        error_msg = f"Document upload error: {str(e)}"
        print(error_msg)
        traceback.print_exc()
        return Response(
            {'error': f'Upload failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@authentication_classes([JWTAuthentication])  # Use JWTAuthentication since that's what you fixed
@permission_classes([IsAuthenticated])
def get_user_documents(request):
    """Get all documents for the authenticated user"""
    try:
        documents = UploadedDocument.objects.filter(user=request.user).order_by('-uploaded_at')
        
        document_list = []
        for doc in documents:
            document_list.append({
                'id': doc.id,
                'file_name': doc.file_name,
                'file_type': doc.file_type,
                'file_size': doc.file_size,
                'file_size_mb': round(doc.file_size / (1024 * 1024), 2) if doc.file_size else 0,
                'uploaded_at': doc.uploaded_at.isoformat(),
                'page_count': doc.page_count,
                'is_processed': doc.is_processed,
                'preview': doc.extracted_text[:500] + "..." if doc.extracted_text and len(doc.extracted_text) > 500 else doc.extracted_text
            })
        
        profile = request.user.userprofile
        tier_limits = profile.get_tier_limits()
        
        return Response({
            'documents': document_list,
            'count': documents.count(),
            'limits': {
                'pdf_analyses_this_month': profile.pdf_analyses_this_month,
                'pdf_limit': tier_limits.get('pdf_limit', 0),
                'can_analyze_pdf': tier_limits.get('can_analyze_pdf', False)
            }
        })
        
    except Exception as e:
        return Response(
            {'error': f'Failed to get documents: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['DELETE'])
@authentication_classes([JWTAuthentication, SessionAuthentication])  # Change to JWT
@permission_classes([IsAuthenticated])
def delete_document(request, document_id):
    """Delete a document"""
    print(f"Deleting document {document_id} for user: {request.user.username}")
    
    try:
        document = UploadedDocument.objects.get(id=document_id, user=request.user)
        
        # Delete file from storage
        if document.file:
            document.file.delete(save=False)
        
        document.delete()
        
        print(f"Document {document_id} deleted successfully")
        
        return Response({
            'success': True,
            'message': f'Document "{document.file_name}" deleted successfully'
        })
        
    except UploadedDocument.DoesNotExist:
        print(f"Document {document_id} not found for user {request.user.username}")
        return Response(
            {'error': 'Document not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print(f"Document deletion error: {str(e)}")
        return Response(
            {'error': f'Deletion failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

def format_analysis_response(analysis_text, question):
    """Format the analysis response for better display"""
    if question:
        # For Q&A format
        return {
            "type": "question_answer",
            "question": question,
            "answer": analysis_text,
            "is_structured": any(marker in analysis_text.lower() for marker in [
                '1.', '2.', '3.', '4.', '5.', '6.', '7.', '8.', '9.',
                '- ', '* ', '• ', 'summary:', 'key points:', 'conclusion:'
            ])
        }
    else:
        # Try to parse structured analysis
        lines = analysis_text.split('\n')
        sections = []
        current_section = {"title": "Analysis", "content": ""}
        
        for line in lines:
            line = line.strip()
            
            # Check if this is a section header
            if (line.startswith('**') and line.endswith('**')) or \
               (line.endswith(':') and len(line) < 50) or \
               line.startswith('#') or \
               line.startswith('##') or \
               (line.isupper() and len(line) < 100 and ' ' in line):
                
                # If we already have content in current section, save it
                if current_section["content"].strip():
                    sections.append(current_section)
                    current_section = {"title": line.replace('**', '').replace(':', ''), "content": ""}
                else:
                    current_section["title"] = line.replace('**', '').replace(':', '')
            else:
                if line:  # Skip empty lines
                    current_section["content"] += line + "\n"
        
        # Add the last section
        if current_section["content"].strip():
            sections.append(current_section)
        
        if len(sections) > 1:
            return {
                "type": "structured_analysis",
                "sections": sections,
                "raw_text": analysis_text
            }
        else:
            return {
                "type": "plain_text",
                "content": analysis_text,
                "is_structured": False
            }
            
@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def check_pdf_limits(request):
    """Check user's PDF analysis limits"""
    try:
        profile = request.user.userprofile
        tier_limits = profile.get_tier_limits()
        
        return Response({
            'success': True,
            'limits': {
                'pdf_analyses_this_month': profile.pdf_analyses_this_month,
                'pdf_limit': tier_limits.get('pdf_limit', 0),
                'remaining': tier_limits.get('pdf_limit', 0) - profile.pdf_analyses_this_month,
                'tier': profile.subscription_tier,
                'reset_date': profile.monthly_reset_date.isoformat() if profile.monthly_reset_date else None,
                'days_until_reset': (profile.monthly_reset_date - timezone.now().date()).days if profile.monthly_reset_date else 0
            },
            'can_analyze': profile.pdf_analyses_this_month < tier_limits.get('pdf_limit', 0),
            'message': f'Used {profile.pdf_analyses_this_month}/{tier_limits.get("pdf_limit", 0)} PDF analyses this month'
        })
    except Exception as e:
        return Response({'error': str(e)}, status=400)
    
    
@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def reset_pdf_counter(request):
    """Reset user's PDF counter (admin only or monthly reset)"""
    profile = request.user.userprofile
    
    # Check if it's time to reset (monthly)
    today = timezone.now().date()
    if profile.monthly_reset_date and today >= profile.monthly_reset_date:
        profile.pdf_analyses_this_month = 0
        profile.data_analyses_this_month = 0
        profile.tokens_this_month = 0
        
        # Set next reset date (1 month from now)
        next_month = today.replace(day=28) + timezone.timedelta(days=4)
        profile.monthly_reset_date = next_month.replace(day=1)
        
        profile.save()
        
        return Response({
            'success': True,
            'message': 'Monthly counters reset successfully',
            'new_limits': {
                'pdf_analyses_this_month': 0,
                'pdf_limit': profile.get_tier_limits().get('pdf_limit', 0),
                'next_reset_date': profile.monthly_reset_date.isoformat()
            }
        })
    else:
        days_left = (profile.monthly_reset_date - today).days
        return Response({
            'success': False,
            'error': f'Monthly reset not due yet. {days_left} days remaining.',
            'reset_date': profile.monthly_reset_date.isoformat() if profile.monthly_reset_date else None
        }, status=400)
        
        
@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def admin_reset_pdf_limit(request, user_id=None):
    """Admin endpoint to reset PDF limit for a user"""
    if not request.user.is_staff:
        return Response({'error': 'Admin access required'}, status=403)
    
    if user_id:
        try:
            user = User.objects.get(id=user_id)
            profile = user.userprofile
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)
    else:
        profile = request.user.userprofile
    
    old_count = profile.pdf_analyses_this_month
    profile.pdf_analyses_this_month = 0
    profile.save()
    
    return Response({
        'success': True,
        'message': f'PDF counter reset for {profile.user.username}',
        'reset_from': old_count,
        'reset_to': 0,
        'user': profile.user.username
    })
    
               
def calculate_user_cost(input_tokens, output_tokens, model="gpt-3.5-turbo", key_type='unknown'):
    """Calculate estimated cost to USER - FREE for certain tiers"""
    # Convert ALL prices to Decimal strings
    pricing = {
        # Free tier models (gpt-3.5-turbo is free on free tier)
        "gpt-3.5-turbo": {"input": Decimal('0.0005'), "output": Decimal('0.0015')},
        "gpt-3.5-turbo-instruct": {"input": Decimal('0.0015'), "output": Decimal('0.0020')},
        "babbage-002": {"input": Decimal('0.0004'), "output": Decimal('0.0004')},
        "davinci-002": {"input": Decimal('0.0020'), "output": Decimal('0.0020')},
        
        # Paid tier models
        "gpt-4o-mini": {"input": Decimal('0.00015'), "output": Decimal('0.00060')},
        "gpt-4o": {"input": Decimal('0.0005'), "output": Decimal('0.0015')},
        "gpt-4-turbo": {"input": Decimal('0.01'), "output": Decimal('0.03')},
        "gpt-4": {"input": Decimal('0.03'), "output": Decimal('0.06')},
        
        # Groq FREE models
        "llama-3.1-8b-instant": {"input": Decimal('0.00'), "output": Decimal('0.00')},
        "mixtral-8x7b-32768": {"input": Decimal('0.00'), "output": Decimal('0.00')},
        
        # Anthropic models
        "claude-3-haiku": {"input": Decimal('0.00025'), "output": Decimal('0.00125')},
        "claude-3-sonnet": {"input": Decimal('0.003'), "output": Decimal('0.015')},
        
        # Gemini models
        "gemini-pro": {"input": Decimal('0.000125'), "output": Decimal('0.000375')},
    }
    
    # Find matching model
    model_key = next((k for k in pricing.keys() if k.lower() == model.lower()), None)
    if not model_key:
        # If model not found, check if it's a gpt-3.5 variant (free tier)
        if 'gpt-3.5' in model.lower() and key_type == 'free_tier':
            model_key = "gpt-3.5-turbo"
        else:
            model_key = "gpt-3.5-turbo"  # Default fallback
    
    model_pricing = pricing[model_key]
    
    # Check if FREE for this user
    is_free = False
    if key_type == 'free_tier':
        # Free tier gets gpt-3.5-turbo for free (up to certain limits)
        if 'gpt-3.5' in model.lower():
            model_pricing = {"input": Decimal('0.00'), "output": Decimal('0.00')}
            is_free = True
    elif model_key in ["llama-3.1-8b-instant", "mixtral-8x7b-32768"]:
        # Groq models are always free
        is_free = True
    
    # Convert tokens to Decimal
    input_tokens_dec = Decimal(str(input_tokens))
    output_tokens_dec = Decimal(str(output_tokens))
    
    # Calculate costs using Decimal arithmetic
    input_cost = (input_tokens_dec / Decimal('1000')) * model_pricing["input"]
    output_cost = (output_tokens_dec / Decimal('1000')) * model_pricing["output"]
    
    total_cost = input_cost + output_cost
    
    # Return just the decimal cost, not a dictionary
    return total_cost

def parse_tokens_from_response(response_json):
    """Parse token counts from OpenAI/Anthropic/Groq response"""
    try:
        usage = response_json.get('usage', {})
        return {
            'input_tokens': usage.get('prompt_tokens', 0),
            'output_tokens': usage.get('completion_tokens', 0),
            'total_tokens': usage.get('total_tokens', 0)
        }
    except:
        return {'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}

# === USER PROFILE VIEWS ===

class UserProfileList(generics.ListAPIView):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAdminUser]
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_profile(request):
    try:
        profile = request.user.userprofile
        serializer = UserProfileSerializer(profile)
        
        # Add usage statistics and billing info
        data = serializer.data
        limits = profile.get_tier_limits()
        profit_info = profile.get_your_profit()
        
        # Check if user is part of reseller program
        reseller_info = None
        try:
            reseller_client = ResellerClient.objects.get(user=request.user)
            reseller_info = {
                'is_reseller_client': True,
                'reseller_name': reseller_client.reseller.name,
                'reseller_code': reseller_client.reseller.code,
                'commission_rate': float(reseller_client.commission_rate),
                'status': reseller_client.status
            }
        except ResellerClient.DoesNotExist:
            reseller_info = {'is_reseller_client': False}
        
        # Check if user is a reseller themselves
        try:
            reseller = Reseller.objects.get(user=request.user)
            reseller_stats = reseller.calculate_stats()
            reseller_info['is_reseller'] = True
            reseller_info['reseller_stats'] = reseller_stats
        except Reseller.DoesNotExist:
            reseller_info['is_reseller'] = False
        
        data['usage'] = {
            'requests_today': profile.requests_today,
            'daily_limit': limits['daily_requests'],
            'tokens_this_month': profile.tokens_this_month,
            'pdf_analyses_this_month': profile.pdf_analyses_this_month,
            'data_analyses_this_month': profile.data_analyses_this_month,
            'has_api_key': profile.has_api_key(),
            'subscription_active': profile.is_subscription_active(),
            'plan_price': float(profile.get_plan_price()),
        }
        
        data['billing'] = {
            'your_profit_per_month': float(profit_info.get('profit', 0)),
            'your_margin_percent': profit_info.get('margin_percent', 0),
            'stripe_customer_id': profile.stripe_customer_id,
            'subscription_status': profile.subscription_status,
        }
        
        data['reseller'] = reseller_info
        
        return Response(data)
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user, level="beginner")
        serializer = UserProfileSerializer(profile)
        return Response(serializer.data)


# === STUDY CONTENT VIEWS ===

class StudyContentListCreate(generics.ListCreateAPIView):
    serializer_class = StudyContentSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter]
    filterset_fields = ['difficulty', 'subject']
    search_fields = ['title', 'content']

    def get_queryset(self):
        return StudyContent.objects.filter(user=self.request.user)


# === AI CHAT VIEWS (PROXY MODEL) ===

class AIConversationList(generics.ListAPIView):
    serializer_class = AIConversationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return AIConversation.objects.filter(user=self.request.user).order_by("-created_at")



import os
from django.conf import settings

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ai_study_helper(request):
    """Enhanced AI chat endpoint with image generation support"""
    print("=== AI CHAT REQUEST STARTED (Enhanced) ===")
    
    # Extract request data
    prompt = request.data.get("prompt", "").strip()
    subject = request.data.get("subject", "General")
    difficulty = request.data.get("difficulty", "Beginner")
    model = request.data.get("model", None)
    
    print(f"Prompt: {prompt[:50]}...")
    print(f"Subject: {subject}, Difficulty: {difficulty}")
    
    # Validate prompt
    if not prompt:
        return Response(
            {"error": "Prompt is required."},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Use the enhanced proxy function with image support
        result = proxy_ai_request_with_images(
            user=request.user,
            prompt=prompt,
            subject=subject,
            difficulty=difficulty,
            model=model
        )
        
        if result.get("success"):
            # Get user profile for usage stats
            profile = request.user.userprofile
            
            return Response({
                "success": True,
                "response": result.get("response", result.get("answer", "")),
                "answer": result.get("answer", ""),
                "image_generated": result.get("image_generated", False),
                "image_url": result.get("image_url"),
                "image_prompt": result.get("image_prompt"),
                "usage": {
                    "requests_today": profile.requests_today,
                    "daily_limit": profile.get_tier_limits()['daily_requests'],
                    "tokens_this_month": profile.tokens_this_month,
                    "tier": profile.subscription_tier,
                    "has_api_key": profile.has_api_key(),
                    "using_fallback": result.get("using_system_fallback", False)
                },
                "costs": {
                    "estimated_user_cost": result.get("estimated_user_cost", 0.00),
                    "your_service_fee": result.get("your_service_fee", 0.0001),
                    "total_tokens": result.get("total_tokens", 0),
                    "provider": result.get("provider", "groq"),
                    "is_free": result.get("is_free", True),
                    "key_source": result.get("key_source", "unknown"),
                    "using_system_key": result.get("using_system_fallback", False),
                    "token_info": {
                        "input_tokens": result.get("input_tokens", 0),
                        "output_tokens": result.get("output_tokens", 0),
                        "total_tokens": result.get("total_tokens", 0)
                    }
                },
                "performance": {
                    "response_time_ms": result.get("response_time_ms", 0),
                    "provider": result.get("provider", "groq")
                },
                "your_profit": float(result.get("your_service_fee", 0.0001))
            })
        else:
            # Return error response
            return Response({
                "success": False,
                "error": result.get("error", "Unknown error"),
                "requires_setup": result.get("requires_setup", False),
                "provider": result.get("provider", "groq"),
                "suggestion": result.get("suggestion", "")
            }, status=status.HTTP_400_BAD_REQUEST if result.get("requires_setup") else status.HTTP_503_SERVICE_UNAVAILABLE)
            
    except Exception as e:
        import traceback
        print(f"=== EXCEPTION CAUGHT ===")
        print(f"Error: {str(e)}")
        traceback.print_exc()
        
        return Response({
            "success": False,
            "error": f"AI request error: {str(e)[:100]}",
            "error_type": type(e).__name__
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@api_view(['POST'])
@authentication_classes([JWTAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def generate_ai_image(request):
    """Dedicated endpoint for AI image generation"""
    print("=== AI IMAGE GENERATION REQUEST ===")
    print(f"User: {request.user.username}")
    print(f"Data: {request.data}")
    
    prompt = request.data.get("prompt", "").strip()
    
    if not prompt:
        return Response(
            {"error": "Image prompt is required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    print(f"Image prompt: {prompt[:100]}...")
    
    try:
        # Get Replicate API token from settings
        api_token = getattr(settings, 'REPLICATE_API_TOKEN', None)
        
        print(f"Replicate token available: {bool(api_token)}")
        print(f"Token length: {len(api_token) if api_token else 0}")
        print(f"Token starts with 'r8_': {api_token.startswith('r8_') if api_token else False}")
        
        if not api_token:
            print("❌ ERROR: No Replicate API token found in settings!")
            print("Please set REPLICATE_API_TOKEN environment variable")
            return Response({
                "success": False,
                "error": "Image generation service not configured",
                "setup_required": True,
                "setup_url": "https://replicate.com/account",
                "message": "Admin needs to configure Replicate API token"
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        
        # Test token validity
        if not api_token.startswith('r8_'):
            print(f"❌ ERROR: Invalid Replicate token format. Should start with 'r8_'")
            return Response({
                "success": False,
                "error": "Invalid Replicate API token format",
                "message": "Token should start with 'r8_'"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Generate the image using the imported function
        from .ai import generate_image_with_replicate_api
        
        print(f"🖼️ Calling generate_image_with_replicate_api...")
        result = generate_image_with_replicate_api(prompt, api_token)
        
        print(f"✅ Image generated successfully: {result.get('image_url', '')[:50]}...")
        
        # Save to conversation history
        conversation = AIConversation.objects.create(
            user=request.user,
            prompt=f"Generate image: {prompt}",
            response=f"Image generated: {result['image_url']}",
            subject="Image Generation",
            difficulty="general",
            user_tier_at_time=request.user.userprofile.subscription_tier,
            model_used=result.get("model", "stability-ai/sdxl"),
            input_tokens=0,
            output_tokens=0,
            total_tokens=0,
            estimated_user_cost=Decimal('0.00'),
            your_service_fee=Decimal('0.0005'),
            api_provider="replicate",
            response_time_ms=0,
            is_image_response=True
        )
        
        # Format the response
        response_text = f"🎨 **Image Generated Successfully!**\n\n"
        response_text += f"**Prompt:** {prompt}\n\n"
        response_text += f"![Generated Image]({result['image_url']})\n\n"
        response_text += f"**Tips:**\n"
        response_text += f"• Click the image to view full size\n"
        response_text += f"• Right-click to save/download\n"
        response_text += f"• For better results, be specific with your descriptions\n\n"
        response_text += f"*Image generated using Stable Diffusion XL*"
        
        return Response({
            "success": True,
            "response": response_text,
            "image_url": result["image_url"],
            "image_prompt": prompt,
            "prediction_id": result.get("prediction_id"),
            "provider": "replicate",
            "model": result.get("model", "stability-ai/sdxl"),
            "costs": {
                "estimated_user_cost": 0.00,
                "your_service_fee": 0.0005,
                "is_free": False
            }
        })
        
    except Exception as e:
        print(f"❌ Image generation error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return Response({
            "success": False,
            "error": f"Image generation failed: {str(e)}",
            "suggestion": "Try a different prompt or try again later",
            "traceback": str(e) if settings.DEBUG else None
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def analyze_pdf(request):
    """PDF analysis endpoint - USER pays for tokens"""
    if not request.FILES.get('pdf'):
        return Response({"error": "PDF file required"}, status=400)
    
    profile = request.user.userprofile
    
    # Check YOUR service limits
    can_send, error_message = profile.can_send_message()
    if not can_send:
        return Response({"error": error_message}, status=429)
    
    # Check if tier allows PDF analysis
    limits = profile.get_tier_limits()
    if not limits.get('can_analyze_pdf', False):
        return Response({
            "error": "PDF analysis not available on your plan",
            "upgrade_required": True,
            "current_tier": profile.subscription_tier
        }, status=402)
    
    # Check PDF limit
    if profile.pdf_analyses_this_month >= limits.get('pdf_limit', 0):
        return Response({
            "error": f"Monthly PDF limit reached ({limits.get('pdf_limit', 0)})",
            "reset_date": (profile.monthly_reset_date.replace(day=1) + timezone.timedelta(days=32)).replace(day=1)
        }, status=429)
    
    # User needs API key
    api_key = profile.get_api_key()
    if not api_key:
        return Response({"error": "API key required for PDF analysis"}, status=400)
    
    # Here you would:
    # 1. Extract text from PDF
    # 2. Send to OpenAI/Anthropic/Groq with user's API key
    # 3. Calculate costs (USER pays - FREE for Groq!)
    # 4. Record YOUR service fee
    
    # For now, mock response
    profile.record_request(tokens=1500, is_pdf=True)
    
    # Log proxy request
    api_log = APIProxyLog.objects.create(
        user=request.user,
        endpoint="pdf_analysis",
        model="gpt-4-vision-preview",
        input_tokens=1000,
        output_tokens=500,
        total_tokens=1500,
        estimated_user_cost=Decimal('0.25'),
        your_service_fee=Decimal('0.05'),  # Higher fee for PDF
        response_time_ms=2500,
        success=True,
        provider="openai",
        request_type="pdf"
    )
    
    # Check if user has a reseller and track commission
    try:
        reseller_client = ResellerClient.objects.get(user=request.user, status='active')
        commission_rate = reseller_client.commission_rate
        commission_amount = Decimal('0.05') * commission_rate
        
        ResellerCommission.objects.create(
            reseller=reseller_client.reseller,
            client=reseller_client,
            transaction=api_log,
            commission_rate=commission_rate,
            commission_amount=commission_amount,
            status='pending'
        )
    except ResellerClient.DoesNotExist:
        pass
    
    return Response({
        "success": True,
        "analysis": "PDF analysis would happen here",
        "pages": 5,
        "summary": "Mock summary of PDF content",
        "cost": {
            "estimated_user_cost": 0.25,
            "your_service_fee": 0.05
        },
        "usage": {
            "pdf_analyses_this_month": profile.pdf_analyses_this_month,
            "pdf_limit": limits.get('pdf_limit', 0)
        }
    })


# === API KEY MANAGEMENT ===

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def set_api_key(request):
    """User sets their own API key with automatic testing"""
    provider = request.data.get('provider', 'groq')
    api_key = request.data.get('api_key', '').strip()
    skip_test = request.data.get('skip_test', False)
    
    if not api_key:
        return Response({"error": "API key required"}, status=400)
    
    profile = request.user.userprofile
    
    # Only allow groq and openai providers
    if provider not in ['groq', 'openai']:
        return Response({"error": "Invalid provider. Only Groq and OpenAI are supported."}, status=400)
    
    # Helper function to test OpenAI key
    def test_openai_key_internal(api_key):
        """Internal function to test OpenAI API key and detect model access"""
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            # 1. Test authentication with models list
            models_response = requests.get(
                "https://api.openai.com/v1/models",
                headers=headers,
                timeout=10
            )
            
            if models_response.status_code != 200:
                return {
                    "success": False,
                    "error": f"Authentication failed: {models_response.status_code}",
                    "status_code": models_response.status_code
                }
            
            # 2. Get available models
            models_data = models_response.json().get('data', [])
            all_available_models = [m['id'] for m in models_data]
            
            # 3. Check subscription info
            key_type = 'unknown'
            credit_balance = Decimal('0.00')
            organization_info = {}
            
            try:
                subscription_response = requests.get(
                    "https://api.openai.com/v1/dashboard/billing/subscription",
                    headers=headers,
                    timeout=10
                )
                
                if subscription_response.status_code == 200:
                    subscription_data = subscription_response.json()
                    plan = subscription_data.get('plan', {}).get('id', '')
                    hard_limit = subscription_data.get('hard_limit_usd', 0)
                    system_limit = subscription_data.get('system_hard_limit_usd', 0)
                    
                    if plan == 'free' or (hard_limit == 0 and system_limit > 0):
                        key_type = 'free_tier'
                        credit_balance = Decimal(str(system_limit))
                    else:
                        key_type = 'pay_as_you_go'
                        credit_balance = Decimal(str(hard_limit))
                    
                    # Get organization info
                    organization_info = {
                        'plan_id': plan,
                        'has_payment_method': subscription_data.get('has_payment_method', False),
                        'account_name': subscription_data.get('account_name', ''),
                        'soft_limit': subscription_data.get('soft_limit_usd', 0),
                        'hard_limit': hard_limit,
                        'system_limit': system_limit
                    }
                    
            except Exception as e:
                print(f"Subscription check failed: {e}")
                # Continue anyway
            
            # 4. Detect specific model access
            available_gpt4_models = [m for m in all_available_models if 'gpt-4' in m.lower()]
            available_gpt35_models = [m for m in all_available_models if 'gpt-3.5' in m.lower()]
            
            # 5. Check for GPT-4 vision models
            has_gpt4_vision = any('vision' in m.lower() for m in all_available_models)
            
            # 6. Check for fine-tuned models access
            has_finetuning_access = any('ft:' in m for m in all_available_models) or any('fine' in m.lower() for m in all_available_models)
            
            # 7. Get usage limits
            usage_limits = {}
            try:
                usage_response = requests.get(
                    "https://api.openai.com/v1/dashboard/billing/usage",
                    headers=headers,
                    timeout=10
                )
                if usage_response.status_code == 200:
                    usage_data = usage_response.json()
                    usage_limits = {
                        'total_usage': usage_data.get('total_usage', 0),
                        'total_granted': usage_data.get('total_granted', 0),
                        'total_available': usage_data.get('total_available', 0),
                        'daily_costs': usage_data.get('daily_costs', [])
                    }
            except:
                pass
            
            # 8. Test actual chat completion with GPT-3.5 (always available for valid keys)
            test_prompt = "Hello, this is a test. Respond with 'OK'."
            can_chat_gpt35 = False
            can_chat_gpt4 = False
            
            try:
                # Test GPT-3.5
                test_response = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": "gpt-3.5-turbo",
                        "messages": [{"role": "user", "content": test_prompt}],
                        "max_tokens": 5,
                        "temperature": 0
                    },
                    timeout=15
                )
                can_chat_gpt35 = test_response.status_code == 200
            except:
                can_chat_gpt35 = False
            
            # Test GPT-4 if available
            if available_gpt4_models:
                try:
                    test_response = requests.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers=headers,
                        json={
                            "model": "gpt-4o-mini",
                            "messages": [{"role": "user", "content": test_prompt}],
                            "max_tokens": 5,
                            "temperature": 0
                        },
                        timeout=15
                    )
                    can_chat_gpt4 = test_response.status_code == 200
                except:
                    can_chat_gpt4 = False
                    # Try with gpt-4 if gpt-4o-mini not available
                    try:
                        test_response = requests.post(
                            "https://api.openai.com/v1/chat/completions",
                            headers=headers,
                            json={
                                "model": "gpt-4",
                                "messages": [{"role": "user", "content": test_prompt}],
                                "max_tokens": 5,
                                "temperature": 0
                            },
                            timeout=15
                        )
                        can_chat_gpt4 = test_response.status_code == 200
                    except:
                        can_chat_gpt4 = False
            
            # 9. Determine account status
            account_status = 'active'
            if credit_balance <= Decimal('0.01') and key_type == 'free_tier':
                account_status = 'free_credits_expired'
            elif credit_balance <= Decimal('1.00') and key_type == 'pay_as_you_go':
                account_status = 'low_balance'
            
            # 10. Categorize models for frontend
            recommended_model = 'gpt-3.5-turbo'
            if can_chat_gpt4 and available_gpt4_models:
                # Pick the cheapest GPT-4 model
                gpt4_models_by_cost = {
                    'gpt-4o-mini': 1,
                    'gpt-4o': 2,
                    'gpt-4-turbo': 3,
                    'gpt-4': 4
                }
                for model in available_gpt4_models:
                    for key in gpt4_models_by_cost.keys():
                        if key in model.lower():
                            recommended_model = model
                            break
                    if recommended_model != 'gpt-3.5-turbo':
                        break
            
            return {
                "success": True,
                "key_type": key_type,
                "credit_balance": float(credit_balance),
                "account_status": account_status,
                "available_gpt4_models": available_gpt4_models,
                "available_gpt35_models": available_gpt35_models,
                "has_gpt4_access": len(available_gpt4_models) > 0,
                "has_gpt4_vision": has_gpt4_vision,
                "has_finetuning_access": has_finetuning_access,
                "can_chat_gpt35": can_chat_gpt35,
                "can_chat_gpt4": can_chat_gpt4,
                "total_models_count": len(all_available_models),
                "organization_info": organization_info,
                "usage_limits": usage_limits,
                "recommended_model": recommended_model,
                "is_free_tier": key_type == 'free_tier',
                "has_payment_method": organization_info.get('has_payment_method', False),
                "can_use_paid_models": key_type == 'pay_as_you_go' and credit_balance > Decimal('0.10')
            }
            
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Connection timeout"
            }
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"Connection error: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}"
            }
    
    # Helper function to test Groq key
    def test_groq_key_internal(api_key):
        """Internal function to test Groq API key"""
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            response = requests.get(
                "https://api.groq.com/openai/v1/models",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    "success": True,
                    "is_free": True,
                    "models_count": len(response.json().get('data', []))
                }
            else:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code}",
                    "status_code": response.status_code
                }
                
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"Connection error: {str(e)}"
            }
    
    # Process based on provider
    if provider == 'openai':
        # Test OpenAI key first (unless skipped)
        if not skip_test:
            test_result = test_openai_key_internal(api_key)
            if not test_result.get('success', False):
                return Response({
                    "success": False,
                    "error": test_result.get('error', 'API key test failed'),
                    "test_result": test_result
                }, status=400)
            
            # Store key with type info
            profile.openai_api_key = api_key
            profile.openai_key_type = test_result.get('key_type', 'unknown')
            profile.openai_key_credit_balance = test_result.get('credit_balance', 0)
            profile.preferred_provider = 'openai'
            
            # Store model access info
            profile.openai_has_gpt4_access = test_result.get('has_gpt4_access', False)
            profile.openai_available_gpt4_models = ','.join(test_result.get('available_gpt4_models', []))[:200]
            profile.openai_available_gpt35_models = ','.join(test_result.get('available_gpt35_models', []))[:200]
            
            # Set appropriate default model
            if test_result.get('key_type') == 'free_tier':
                # Free tier - only gpt-3.5 models
                profile.preferred_model = 'gpt-3.5-turbo'
            else:
                # Paid account
                if test_result.get('has_gpt4_access', False):
                    profile.preferred_model = test_result.get('recommended_model', 'gpt-4o-mini')
                else:
                    profile.preferred_model = 'gpt-3.5-turbo'  # Fallback
            
            profile.save()
            
            return Response({
                "success": True,
                "message": f"OpenAI API key saved and tested",
                "provider": provider,
                "key_type": test_result.get('key_type', 'unknown'),
                "is_free": test_result.get('key_type') == 'free_tier',
                "credit_balance": test_result.get('credit_balance', 0),
                "has_gpt4_access": test_result.get('has_gpt4_access', False),
                "has_gpt4_vision": test_result.get('has_gpt4_vision', False),
                "can_chat_gpt35": test_result.get('can_chat_gpt35', False),
                "can_chat_gpt4": test_result.get('can_chat_gpt4', False),
                "total_models": test_result.get('total_models_count', 0),
                "available_gpt4_models": test_result.get('available_gpt4_models', []),
                "available_gpt35_models": test_result.get('available_gpt35_models', []),
                "recommended_model": test_result.get('recommended_model', 'gpt-3.5-turbo'),
                "free_tokens": "Free tier: Limited GPT-3.5 access" if test_result.get('key_type') == 'free_tier' else "Pay-as-you-go",
                "has_api_key": profile.has_api_key(),
                "test_result": test_result
            })
        else:
            # Skip test mode - just save the key
            profile.openai_api_key = api_key
            profile.openai_key_type = 'unknown'
            profile.preferred_provider = 'openai'
            profile.preferred_model = 'gpt-3.5-turbo'  # Safe default
            profile.save()
            
            return Response({
                "success": True,
                "message": "OpenAI API key saved (not tested)",
                "provider": provider,
                "warning": "Key was not tested for validity",
                "is_free": False,  # Unknown
                "has_api_key": profile.has_api_key()
            })
            
    elif provider == 'groq':
        # Test Groq key
        test_result = test_groq_key_internal(api_key)
        if not test_result.get('success', False):
            return Response({
                "success": False,
                "error": test_result.get('error', 'API key test failed')
            }, status=400)
        
        profile.groq_api_key = api_key
        profile.preferred_provider = 'groq'
        profile.preferred_model = 'llama-3.1-8b-instant'
        profile.save()
        
        return Response({
            "success": True,
            "message": "Groq API key saved and tested",
            "provider": provider,
            "is_free": True,
            "free_tokens": "5,000,000 tokens/month",
            "has_api_key": profile.has_api_key(),
            "test_result": test_result
        })
        
    elif provider == 'anthropic':
        # For Anthropic, we'll do a simple test
        try:
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }
            
            response = requests.get(
                "https://api.anthropic.com/v1/models",
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                return Response({
                    "success": False,
                    "error": f"Anthropic API error: {response.status_code}"
                }, status=400)
                
        except requests.exceptions.RequestException as e:
            return Response({
                "success": False,
                "error": f"Connection error: {str(e)}"
            }, status=400)
        
        profile.anthropic_api_key = api_key
        profile.preferred_provider = 'anthropic'
        profile.preferred_model = 'claude-3-haiku'
        profile.save()
        
        return Response({
            "success": True,
            "message": "Anthropic API key saved",
            "provider": provider,
            "is_free": False,
            "free_tokens": "No free tier available",
            "has_api_key": profile.has_api_key()
        })
        
    elif provider == 'gemini':
        # For Gemini, we'll do a simple test
        try:
            headers = {
                "Content-Type": "application/json"
            }
            
            # Gemini has a different endpoint structure
            response = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={api_key}",
                headers=headers,
                json={"contents": [{"parts": [{"text": "test"}]}]},
                timeout=10
            )
            
            if response.status_code != 200:
                return Response({
                    "success": False,
                    "error": f"Gemini API error: {response.status_code}"
                }, status=400)
                
        except requests.exceptions.RequestException as e:
            return Response({
                "success": False,
                "error": f"Connection error: {str(e)}"
            }, status=400)
        
        profile.gemini_api_key = api_key
        profile.preferred_provider = 'gemini'
        profile.preferred_model = 'gemini-pro'
        profile.save()
        
        return Response({
            "success": True,
            "message": "Google Gemini API key saved",
            "provider": provider,
            "is_free": False,
            "free_tokens": "60 requests/minute (Free tier available)",
            "has_api_key": profile.has_api_key()
        })
    else:
        return Response({"error": "Invalid provider"}, status=400)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def request_auto_api_setup(request):
    """Request automated API account creation"""
    provider = request.data.get('provider', 'groq')
    
    # Check if already exists
    existing = APIAutoSetupRequest.objects.filter(
        user=request.user,
        provider=provider,
        status__in=['pending', 'processing']
    ).exists()
    
    if existing:
        return Response({
            "error": f"{provider.capitalize()} setup already in progress"
        }, status=400)
    
    # Create setup request
    setup_request = APIAutoSetupRequest.objects.create(
        user=request.user,
        provider=provider,
        status='pending'
    )
    
    # Generate setup instructions (especially for Groq - FREE!)
    if provider == 'groq':
        referral_id = f"studypilot_{request.user.id}_{int(timezone.now().timestamp())}"
        instructions = f"""
        🔥 **FREE AI ACCESS WITH GROQ!**
        
        ⚡ **Groq gives you 5 MILLION tokens/month for FREE!**
        🎯 **No credit card required!**
        ⏰ **Takes 2 minutes to set up**
        
        1. **Go to**: https://console.groq.com/signup
        2. **Sign up** with your email: {request.user.email}
        3. **Verify your email** (check spam folder)
        4. **Get your API key** from: https://console.groq.com/keys
        5. **Copy and paste** your API key here
        
        💡 **Tip**: Groq is faster than ChatGPT and completely FREE!
        📚 **Free Models**: llama-3.1-8b-instant, mixtral-8x7b-32768
        
        Your referral code: {referral_id}
        Support: support@groq.com
        """
        
        setup_request.setup_instructions = instructions
        setup_request.status = 'completed'
        setup_request.save()
    
    return Response({
        "success": True,
        "message": f"{provider.capitalize()} account setup requested",
        "request_id": setup_request.id,
        "status": "completed" if provider == 'groq' else "pending",
        "estimated_time": "2 minutes" if provider == 'groq' else "5-10 minutes",
        "is_free": provider == 'groq',
        "instructions": instructions if provider == 'groq' else None
    })


# === RESELLER MANAGEMENT VIEWS ===

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def apply_reseller(request):
    """Apply to become a reseller"""
    try:
        # Check if already a reseller
        existing = Reseller.objects.filter(user=request.user).exists()
        if existing:
            return Response({"error": "You are already a reseller"}, status=400)
        
        # Create reseller application
        name = request.data.get('name', f"{request.user.username}'s Reseller")
        company = request.data.get('company', '')
        website = request.data.get('website', '')
        commission_rate = Decimal(request.data.get('commission_rate', '0.30'))  # Default 30%
        
        # Validate commission rate
        if commission_rate > Decimal('0.50'):  # Max 50%
            commission_rate = Decimal('0.50')
        
        reseller = Reseller.objects.create(
            user=request.user,
            name=name,
            company=company,
            website=website,
            default_commission_rate=commission_rate,
            status='pending'  # Requires admin approval
        )
        
        return Response({
            "success": True,
            "message": "Reseller application submitted for admin approval",
            "reseller_id": reseller.id,
            "code": reseller.code,
            "commission_rate": float(commission_rate),
            "status": "pending"
        })
        
    except Exception as e:
        return Response({
            "error": f"Application failed: {str(e)}"
        }, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_reseller_dashboard(request):
    """Get reseller dashboard data"""
    try:
        reseller = Reseller.objects.get(user=request.user)
        
        # Calculate stats
        stats = reseller.calculate_stats()
        
        # Get recent clients
        recent_clients = ResellerClient.objects.filter(
            reseller=reseller
        ).order_by('-created_at')[:10]
        
        # Get pending commissions
        pending_commissions = ResellerCommission.objects.filter(
            reseller=reseller,
            status='pending'
        ).order_by('-created_at')[:10]
        
        # Get payout history
        payouts = ResellerPayout.objects.filter(
            reseller=reseller
        ).order_by('-created_at')[:5]
        
        return Response({
            "success": True,
            "reseller": {
                "id": reseller.id,
                "name": reseller.name,
                "code": reseller.code,
                "status": reseller.status,
                "default_commission_rate": float(reseller.default_commission_rate),
                "total_earnings": float(stats['total_earnings']),
                "available_balance": float(stats['available_balance']),
                "total_clients": stats['total_clients'],
                "active_clients": stats['active_clients'],
                "signup_url": f"/register?reseller_code={reseller.code}"
            },
            "stats": stats,
            "recent_clients": [
                {
                    "id": client.id,
                    "user": client.user.username,
                    "email": client.user.email,
                    "status": client.status,
                    "commission_rate": float(client.commission_rate),
                    "joined": client.created_at.isoformat(),
                    "total_commission": float(client.calculate_total_commission())
                }
                for client in recent_clients
            ],
            "pending_commissions": [
                {
                    "id": commission.id,
                    "client": commission.client.user.username,
                    "amount": float(commission.commission_amount),
                    "rate": float(commission.commission_rate),
                    "date": commission.created_at.isoformat(),
                    "transaction_type": commission.transaction.request_type if commission.transaction else "unknown"
                }
                for commission in pending_commissions
            ],
            "payouts": [
                {
                    "id": payout.id,
                    "amount": float(payout.amount),
                    "status": payout.status,
                    "method": payout.payout_method,
                    "date": payout.created_at.isoformat(),
                    "notes": payout.notes
                }
                for payout in payouts
            ]
        })
        
    except Reseller.DoesNotExist:
        return Response({
            "success": False,
            "error": "You are not a reseller",
            "apply_url": "/apply-reseller/"
        })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def request_reseller_payout(request):
    """Request a payout of earned commissions"""
    try:
        reseller = Reseller.objects.get(user=request.user)
        
        # Check available balance
        stats = reseller.calculate_stats()
        available_balance = stats['available_balance']
        
        if available_balance < Decimal('10.00'):
            return Response({
                "error": f"Minimum payout is $10.00. Your available balance is ${float(available_balance):.2f}"
            }, status=400)
        
        # Create payout request
        payout_method = request.data.get('payout_method', 'stripe')
        amount = Decimal(str(request.data.get('amount', float(available_balance))))
        
        # Validate amount
        if amount > available_balance:
            amount = available_balance
        
        payout = ResellerPayout.objects.create(
            reseller=reseller,
            amount=amount,
            payout_method=payout_method,
            status='pending',
            notes=f"Payout requested by {request.user.username}"
        )
        
        # Mark commissions as paid
        commissions = ResellerCommission.objects.filter(
            reseller=reseller,
            status='pending'
        )
        
        for commission in commissions:
            if amount <= Decimal('0'):
                break
            commission.status = 'paid'
            commission.payout = payout
            commission.save()
            amount -= commission.commission_amount
        
        return Response({
            "success": True,
            "message": f"Payout request submitted for ${float(payout.amount):.2f}",
            "payout_id": payout.id,
            "amount": float(payout.amount),
            "status": "pending",
            "method": payout_method,
            "estimated_processing": "3-5 business days"
        })
        
    except Reseller.DoesNotExist:
        return Response({"error": "You are not a reseller"}, status=403)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_reseller_info(request, code):
    """Get public information about a reseller"""
    try:
        reseller = Reseller.objects.get(code=code, is_active=True, status='active')
        
        return Response({
            "success": True,
            "reseller": {
                "name": reseller.name,
                "company": reseller.company,
                "website": reseller.website,
                "description": reseller.description,
                "code": reseller.code,
                "signup_bonus": reseller.signup_bonus,
                "features": [
                    "White-label AI Study Platform",
                    "FREE Groq API Integration (5M tokens/month)",
                    "Premium study tools",
                    f"Special commission rate: {float(reseller.default_commission_rate * 100)}%"
                ]
            }
        })
        
    except Reseller.DoesNotExist:
        return Response({
            "success": False,
            "error": "Reseller not found or inactive"
        }, status=404)


# === BILLING & SUBSCRIPTION ===

def get_subscription_plans_data():
    """Get subscription plans users pay YOU for"""
    return [
        {
            "name": "Free",
            "tier": "free",
            "monthly_price": 0,
            "daily_requests": 50,
            "features": [
                "50 requests/day",
                "Basic AI proxy service",
                "Study tracking",
                "Manual API key setup",
                "Access to FREE Groq API"
            ],
            "your_profit_margin": "N/A",
            "popular": False
        },
        {
            "name": "Premium",
            "tier": "premium", 
            "monthly_price": 19.99,
            "daily_requests": 1000,
            "features": [
                "1000 requests/day",
                "PDF analysis (5/month)",
                "Priority support",
                "Advanced analytics",
                "Auto API setup assistance",
                "Reseller commission eligibility"
            ],
            "your_profit_margin": "98.5%",
            "popular": True
        },
        {
            "name": "Unlimited",
            "tier": "unlimited",
            "monthly_price": 49.99,
            "daily_requests": 5000,
            "features": [
                "5000 requests/day",
                "PDF analysis (20/month)",
                "Data analysis (10/month)",
                "Unlimited support",
                "Auto API setup",
                "Highest priority",
                "Reseller commission eligibility"
            ],
            "your_profit_margin": "98.8%",
            "popular": False
        }
    ]


@api_view(['GET'])
@permission_classes([AllowAny])
def get_subscription_plans(request):
    """Get available subscription plans (users pay YOU)"""
    reseller_code = request.GET.get('reseller_code', None)
    reseller_discount = None
    
    if reseller_code:
        try:
            reseller = Reseller.objects.get(code=reseller_code, is_active=True, status='active')
            reseller_discount = {
                'reseller_name': reseller.name,
                'discount_percent': float(reseller.discount_percent) if reseller.discount_percent else 0,
                'signup_bonus': reseller.signup_bonus
            }
        except Reseller.DoesNotExist:
            pass
    
    plans = get_subscription_plans_data()
    
    # Add YOUR profit calculations
    for plan in plans:
        if plan['monthly_price'] > 0:
            price = Decimal(str(plan['monthly_price']))
            
            # Apply reseller discount if applicable
            if reseller_discount and reseller_discount['discount_percent'] > 0:
                discount = price * (Decimal(str(reseller_discount['discount_percent'])) / 100)
                plan['original_price'] = float(price)
                price = price - discount
                plan['monthly_price'] = float(price)
                plan['discount_percent'] = reseller_discount['discount_percent']
            
            stripe_fee = price * Decimal('0.029') + Decimal('0.30')
            hosting = Decimal('0.10')
            profit = price - stripe_fee - hosting
            margin = (profit / price) * 100
            plan['your_profit_per_user'] = float(profit)
            plan['your_margin_percent'] = round(float(margin), 1)
    
    return Response({
        "success": True,
        "plans": plans,
        "reseller": reseller_discount,
        "note": "Users provide their own FREE Groq API keys and pay AI providers directly",
        "your_business_model": "White-label AI proxy service with 99%+ margins"
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_checkout_session(request):
    """Create Stripe checkout session (user pays YOU)"""
    plan_tier = request.data.get('plan_tier', 'premium')
    reseller_code = request.data.get('reseller_code', None)
    
    # Calculate price
    if plan_tier == 'premium':
        base_price = Decimal('19.99')
    elif plan_tier == 'unlimited':
        base_price = Decimal('49.99')
    else:
        base_price = Decimal('0.00')
    
    # Apply reseller discount if applicable
    discount_percent = 0
    if reseller_code:
        try:
            reseller = Reseller.objects.get(code=reseller_code, is_active=True)
            discount_percent = reseller.discount_percent or 0
        except Reseller.DoesNotExist:
            pass
    
    if discount_percent > 0:
        discount = base_price * (Decimal(str(discount_percent)) / 100)
        final_price = base_price - discount
    else:
        final_price = base_price
    
    # In reality, this would:
    # 1. Create Stripe checkout session
    # 2. Return session ID to frontend
    # 3. Webhook would update user profile
    
    # Mock response
    session_id = f"cs_test_{uuid.uuid4().hex[:24]}"
    
    return Response({
        "success": True,
        "session_id": session_id,
        "url": f"https://checkout.stripe.com/c/pay/{session_id}",
        "plan": plan_tier,
        "price": float(final_price),
        "original_price": float(base_price) if discount_percent > 0 else None,
        "discount_percent": discount_percent if discount_percent > 0 else None,
        "reseller_code": reseller_code
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_subscription(request):
    """Cancel user's subscription (with YOU)"""
    profile = request.user.userprofile
    
    if profile.subscription_tier == 'free':
        return Response({"error": "No active subscription"}, status=400)
    
    # Mock cancellation
    old_tier = profile.subscription_tier
    profile.subscription_tier = 'free'
    profile.subscription_status = 'canceled'
    profile.save()
    
    return Response({
        "success": True,
        "message": f"Subscription canceled. Downgraded to Free tier.",
        "old_tier": old_tier,
        "new_tier": "free",
        "refund_note": "No refunds for partial months per terms"
    })


# === USAGE & ANALYTICS ===

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_usage_stats(request):
    """Get usage statistics"""
    try:
        profile = request.user.userprofile
        limits = profile.get_tier_limits()
        
        # Calculate costs user has paid to AI providers
        user_ai_costs = AIConversation.objects.filter(
            user=request.user,
            created_at__month=timezone.now().month
        ).aggregate(total_cost=models.Sum('estimated_user_cost'))['total_cost'] or 0
        
        # Calculate YOUR profits from this user
        your_profits = AIConversation.objects.filter(
            user=request.user,
            created_at__month=timezone.now().month
        ).aggregate(total_profit=models.Sum('your_service_fee'))['total_profit'] or 0
        
        # Check reseller status
        reseller_info = None
        try:
            reseller_client = ResellerClient.objects.get(user=request.user)
            reseller_info = {
                'reseller_name': reseller_client.reseller.name,
                'commission_rate': float(reseller_client.commission_rate),
                'total_commission': float(reseller_client.calculate_total_commission()),
                'status': reseller_client.status
            }
        except ResellerClient.DoesNotExist:
            pass
        
        return Response({
            "success": True,
            "profile": {
                "tier": profile.subscription_tier,
                "subscription_status": profile.subscription_status,
                "has_api_key": profile.has_api_key(),
                "preferred_provider": profile.preferred_provider,
                "provider_info": profile.get_provider_info()
            },
            "usage": {
                "requests_today": profile.requests_today,
                "daily_limit": limits['daily_requests'],
                "tokens_this_month": profile.tokens_this_month,
                "pdf_analyses_this_month": profile.pdf_analyses_this_month,
                "data_analyses_this_month": profile.data_analyses_this_month,
                "monthly_reset": profile.monthly_reset_date
            },
            "financial": {
                "your_subscription_price": float(profile.get_plan_price()),
                "your_estimated_profit": float(profile.get_your_profit().get('profit', 0)),
                "your_profit_margin": profile.get_your_profit().get('margin_percent', 0),
                "user_ai_costs_this_month": float(user_ai_costs),  # User pays AI providers
                "your_service_fees_this_month": float(your_profits)  # YOUR profit
            },
            "reseller": reseller_info
        })
        
    except UserProfile.DoesNotExist:
        return Response({
            "success": False,
            "error": "User profile not found"
        }, status=404)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_your_profit_dashboard(request):
    """Admin view of YOUR profits"""
    if not request.user.is_staff:
        return Response({"error": "Admin access required"}, status=403)
    
    # Calculate YOUR overall profits
    today = timezone.now().date()
    
    # Update analytics
    analytics = ProfitAnalytics.update_daily_analytics()
    
    # Get recent transactions
    recent_tx = BillingTransaction.objects.filter(
        status='succeeded',
        timestamp__date=today
    )[:10]
    
    # Calculate metrics
    total_active_users = UserProfile.objects.filter(
        subscription_status='active'
    ).count()
    
    total_premium_users = UserProfile.objects.filter(
        subscription_tier='premium',
        subscription_status='active'
    ).count()
    
    total_unlimited_users = UserProfile.objects.filter(
        subscription_tier='unlimited', 
        subscription_status='active'
    ).count()
    
    # Reseller metrics
    total_resellers = Reseller.objects.filter(status='active', is_active=True).count()
    total_reseller_clients = ResellerClient.objects.filter(status='active').count()
    
    # YOUR monthly recurring revenue (MRR)
    mrr = (
        total_premium_users * Decimal('19.99') +
        total_unlimited_users * Decimal('49.99')
    )
    
    # YOUR estimated monthly profit
    estimated_monthly_profit = mrr * Decimal('0.985')  # 98.5% margin
    
    # Reseller commission liabilities
    pending_commissions = ResellerCommission.objects.filter(status='pending').aggregate(
        total=models.Sum('commission_amount')
    )['total'] or Decimal('0.00')
    
    return Response({
        "success": True,
        "your_business_metrics": {
            "total_users": User.objects.count(),
            "active_subscribers": total_active_users,
            "premium_users": total_premium_users,
            "unlimited_users": total_unlimited_users,
            "monthly_recurring_revenue": float(mrr),
            "estimated_monthly_profit": float(estimated_monthly_profit),
            "estimated_profit_margin": "98.5%",
            "today_date": today.isoformat(),
            "reseller_program": {
                "total_resellers": total_resellers,
                "total_reseller_clients": total_reseller_clients,
                "pending_commissions": float(pending_commissions)
            }
        },
        "today_performance": {
            "revenue": float(analytics.total_revenue),
            "costs": float(analytics.total_costs),
            "net_profit": float(analytics.net_profit),
            "profit_margin": float(analytics.profit_margin),
            "total_requests": analytics.total_requests,
            "total_service_fees": float(analytics.total_your_service_fees)
        },
        "recent_transactions": [
            {
                "user": tx.user.username,
                "amount": float(tx.amount),
                "time": tx.timestamp.time().isoformat()[:5],
                "your_profit": float(tx.your_profit),
                "your_margin": tx.profit_margin
            }
            for tx in recent_tx
        ],
        "note": "All token costs are paid by users directly to AI providers (FREE with Groq!)"
    })


# === ADMIN ENDPOINTS ===

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reset_daily_counters(request):
    """Admin endpoint to reset daily counters"""
    if not request.user.is_staff:
        return Response({"error": "Admin access required"}, status=403)
    
    updated = UserProfile.objects.update(
        requests_today=0,
        requests_this_minute=0,
        last_reset_date=timezone.now().date()
    )
    
    return Response({
        "success": True,
        "message": f"Reset daily counters for {updated} users",
        "reset_date": timezone.now().date().isoformat()
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reset_monthly_counters(request):
    """Admin endpoint to reset monthly counters"""
    if not request.user.is_staff:
        return Response({"error": "Admin access required"}, status=403)
    
    updated = UserProfile.objects.update(
        tokens_this_month=0,
        pdf_analyses_this_month=0,
        data_analyses_this_month=0,
        monthly_reset_date=timezone.now().date()
    )
    
    return Response({
        "success": True,
        "message": f"Reset monthly counters for {updated} users",
        "reset_date": timezone.now().date().isoformat()
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_reseller_list(request):
    """Admin view of all resellers"""
    if not request.user.is_staff:
        return Response({"error": "Admin access required"}, status=403)
    
    resellers = Reseller.objects.all().order_by('-created_at')
    
    return Response({
        "success": True,
        "resellers": [
            {
                "id": r.id,
                "name": r.name,
                "user": r.user.username,
                "code": r.code,
                "status": r.status,
                "is_active": r.is_active,
                "default_commission_rate": float(r.default_commission_rate),
                "total_clients": r.resellerclient_set.count(),
                "total_earnings": float(r.calculate_stats()['total_earnings']),
                "created_at": r.created_at.isoformat()
            }
            for r in resellers
        ]
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_approve_reseller(request, reseller_id):
    """Admin approve a reseller application"""
    if not request.user.is_staff:
        return Response({"error": "Admin access required"}, status=403)
    
    try:
        reseller = Reseller.objects.get(id=reseller_id)
        reseller.status = 'active'
        reseller.is_active = True
        reseller.approved_by = request.user
        reseller.approved_at = timezone.now()
        reseller.save()
        
        return Response({
            "success": True,
            "message": f"Reseller {reseller.name} approved",
            "reseller": {
                "id": reseller.id,
                "name": reseller.name,
                "code": reseller.code,
                "status": reseller.status
            }
        })
        
    except Reseller.DoesNotExist:
        return Response({"error": "Reseller not found"}, status=404)


# === BATCH PROCESSING ===

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def batch_ai_questions(request):
    """Process multiple questions at once"""
    questions = request.data.get("questions", [])
    
    if not isinstance(questions, list) or len(questions) > 10:
        return Response({
            "error": "Please provide up to 10 questions in a list"
        }, status=400)
    
    profile = request.user.userprofile
    
    # Check YOUR service limits
    required_quota = len(questions)
    limits = profile.get_tier_limits()
    if profile.requests_today + required_quota > limits['daily_requests']:
        return Response({
            "error": f"Insufficient quota. Need {required_quota} requests, have {limits['daily_requests'] - profile.requests_today} remaining"
        }, status=429)
    
    # Check API key
    api_key = profile.get_api_key()
    if not api_key:
        return Response({"error": "API key required"}, status=400)
    
    results = []
    total_tokens = 0
    total_your_profit = Decimal('0.00')
    
    for question in questions:
        if not isinstance(question, dict):
            continue
            
        prompt = question.get("prompt", "").strip()
        subject = question.get("subject", "General")
        
        if not prompt:
            continue
        
        try:
            # In reality, you would make batch API call
            # For now, simulate
            mock_tokens = 500
            user_cost = calculate_user_cost(300, 200)
            your_fee = Decimal('0.0001')
            
            conversation = AIConversation.objects.create(
                user=request.user,
                prompt=prompt,
                response=f"Mock answer for: {prompt[:50]}...",
                subject=subject,
                difficulty="medium",
                input_tokens=300,
                output_tokens=200,
                total_tokens=mock_tokens,
                estimated_user_cost=user_cost,
                your_service_fee=your_fee,
                api_provider=profile.preferred_provider
            )
            
            results.append({
                "question": prompt,
                "answer": conversation.response,
                "success": True,
                "your_profit": float(your_fee)
            })
            
            total_tokens += mock_tokens
            total_your_profit += your_fee
            
        except Exception as e:
            results.append({
                "question": prompt,
                "error": str(e)[:100],
                "success": False
            })
    
    # Update profile usage
    profile.record_request(tokens=total_tokens)
    
    return Response({
        "success": True,
        "results": results,
        "summary": {
            "total_questions": len(questions),
            "successful": len([r for r in results if r.get("success")]),
            "total_tokens": total_tokens,
            "total_your_profit": float(total_your_profit),
            "new_daily_usage": profile.requests_today
        }
    })


# === STRIPE WEBHOOK HANDLER (SIMPLIFIED) ===

@api_view(['POST'])
@permission_classes([AllowAny])
def stripe_webhook(request):
    """Handle Stripe webhooks for YOUR billing"""
    # In reality, verify Stripe signature
    
    event_type = request.data.get('type', '')
    data = request.data.get('data', {})
    
    if event_type == 'checkout.session.completed':
        # User completed checkout with YOU
        session = data.get('object', {})
        customer_email = session.get('customer_email', '')
        subscription_id = session.get('subscription', '')
        price_id = session.get('metadata', {}).get('price_id', '')
        reseller_code = session.get('metadata', {}).get('reseller_code', None)
        
        # Find user by email
        try:
            user = User.objects.get(email=customer_email)
            profile = user.userprofile
            
            # Update subscription
            if 'premium' in price_id:
                profile.subscription_tier = 'premium'
            elif 'unlimited' in price_id:
                profile.subscription_tier = 'unlimited'
            
            profile.subscription_status = 'active'
            profile.stripe_customer_id = session.get('customer', '')
            profile.stripe_subscription_id = subscription_id
            profile.current_period_start = timezone.now()
            profile.current_period_end = timezone.now() + timezone.timedelta(days=30)
            profile.save()
            
            # Create billing transaction
            amount = session.get('amount_total', 0) / 100  # Convert from cents
            transaction = BillingTransaction.objects.create(
                user=user,
                amount=Decimal(str(amount)),
                plan=SubscriptionPlan.objects.filter(
                    monthly_price=amount
                ).first(),
                period_start=timezone.now().date(),
                period_end=(timezone.now() + timezone.timedelta(days=30)).date(),
                stripe_fee=Decimal(str(amount)) * Decimal('0.029') + Decimal('0.30'),
                stripe_payment_intent_id=session.get('payment_intent', ''),
                stripe_invoice_id=session.get('invoice', ''),
                status='succeeded'
            )
            
            # Handle reseller commission if applicable
            if reseller_code:
                try:
                    reseller = Reseller.objects.get(code=reseller_code, is_active=True)
                    # Check if user is already a client
                    try:
                        reseller_client = ResellerClient.objects.get(user=user, reseller=reseller)
                    except ResellerClient.DoesNotExist:
                        # Create new reseller client relationship
                        reseller_client = ResellerClient.objects.create(
                            reseller=reseller,
                            user=user,
                            commission_rate=reseller.default_commission_rate,
                            status='active'
                        )
                    
                    # Create commission for subscription payment
                    commission_rate = reseller_client.commission_rate
                    commission_amount = transaction.amount * commission_rate
                    
                    ResellerCommission.objects.create(
                        reseller=reseller,
                        client=reseller_client,
                        transaction_type='subscription',
                        subscription_transaction=transaction,
                        commission_rate=commission_rate,
                        commission_amount=commission_amount,
                        status='pending',
                        notes=f"Subscription payment for {profile.subscription_tier} tier"
                    )
                    
                except Reseller.DoesNotExist:
                    pass
            
        except User.DoesNotExist:
            pass
    
    elif event_type == 'customer.subscription.deleted':
        # User canceled subscription with YOU
        subscription = data.get('object', {})
        subscription_id = subscription.get('id', '')
        
        # Find user by subscription ID
        profiles = UserProfile.objects.filter(stripe_subscription_id=subscription_id)
        for profile in profiles:
            profile.subscription_tier = 'free'
            profile.subscription_status = 'canceled'
            profile.save()
    
    return Response({"received": True})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def clear_ai_memory(request):
    """Clear user's conversation history"""
    deleted_count, _ = AIConversation.objects.filter(user=request.user).delete()
    
    return Response({
        "success": True,
        "message": f"Cleared {deleted_count} previous conversations."
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def setup_initial_data(request):
    """Simple setup"""
    if not request.user.is_staff:
        return Response({"error": "Admin access required"}, status=403)
    
    # Create default subscription plans (YOUR plans)
    plans_data = [
        {
            'name': 'Free',
            'tier': 'free',
            'monthly_price': 0,
            'description': 'Basic access with manual API setup',
            'features': ['50 requests/day', 'Basic support'],
            'stripe_price_id': 'price_free',
            'suggested_daily_requests': 50,
            'your_cost_per_user': Decimal('0.10')
        },
        {
            'name': 'Premium',
            'tier': 'premium',
            'monthly_price': Decimal('19.99'),
            'description': 'Enhanced limits with PDF analysis',
            'features': ['1000 requests/day', 'PDF analysis', 'Priority support'],
            'stripe_price_id': 'price_premium_1999',
            'suggested_daily_requests': 1000,
            'your_cost_per_user': Decimal('0.40')
        },
        {
            'name': 'Unlimited',
            'tier': 'unlimited',
            'monthly_price': Decimal('49.99'),
            'description': 'Maximum limits with all features',
            'features': ['5000 requests/day', 'PDF & Data analysis', 'Unlimited support'],
            'stripe_price_id': 'price_unlimited_4999',
            'suggested_daily_requests': 5000,
            'your_cost_per_user': Decimal('0.60')
        }
    ]
    
    created_count = 0
    for plan_data in plans_data:
        plan, created = SubscriptionPlan.objects.update_or_create(
            tier=plan_data['tier'],
            defaults=plan_data
        )
        if created:
            created_count += 1
    
    return Response({
        'success': True,
        'message': f'Created/updated {created_count} subscription plans',
        'your_profit_note': 'You earn 99%+ margins while users pay AI providers directly (FREE with Groq!)'
    })


# === NEW VIEWS FROM THE SECOND FILE ===

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def request_groq_auto_setup(request):
    """Request automated GROQ account creation (FREE!)"""
    user = request.user
    
    # Generate setup instructions
    referral_id = f"studypilot_{int(timezone.now().timestamp())}"
    
    instructions = f"""
    🔥 **FREE AI ACCESS WITH GROQ!**
    
    ⚡ **Groq gives you 5 MILLION tokens/month for FREE!**
    🎯 **No credit card required!**
    ⏰ **Takes 2 minutes to set up**
    
    1. **Go to**: https://console.groq.com/signup
    2. **Sign up** with your email
    3. **Verify your email** (check spam folder)
    4. **Get your API key** from: https://console.groq.com/keys
    5. **Copy and paste** your API key here
    
    💡 **Tip**: Groq is faster than ChatGPT and completely FREE!
    📚 **Free Models**: llama-3.1-8b-instant, mixtral-8x7b-32768
    
    Your referral code: {referral_id}
    Support: support@groq.com
    """
    
    # Create setup request record
    APIAutoSetupRequest.objects.create(
        user=user,
        provider='groq',
        status='completed',
        setup_instructions=instructions,
        account_email=user.email,
        free_tokens_info="5,000,000 tokens/month"
    )
    
    return Response({
        "success": True,
        "message": "GROQ setup instructions ready!",
        "is_free": True,
        "free_tokens": "5,000,000 tokens/month",
        "instructions": instructions,
        "signup_url": "https://console.groq.com/signup",
        "api_keys_url": "https://console.groq.com/keys",
        "referral_id": referral_id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def check_rate_limit(request):
    """Check if user can send a message"""
    try:
        profile = request.user.userprofile
        can_send, message = profile.can_send_message()
        
        return Response({
            "success": True,
            "can_send": can_send,
            "message": message,
            "usage": {
                "requests_today": profile.requests_today,
                "daily_limit": profile.get_tier_limits()['daily_requests'],
                "usage_percentage": min(100, (profile.requests_today / profile.get_tier_limits()['daily_requests']) * 100) if profile.get_tier_limits()['daily_requests'] > 0 else 0,
                "messages_remaining": max(0, profile.get_tier_limits()['daily_requests'] - profile.requests_today),
                "tier": profile.subscription_tier
            }
        })
        
    except UserProfile.DoesNotExist:
        return Response({
            "success": False,
            "error": "User profile not found"
        }, status=404)
        
        
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def test_openai_key(request):
    """Test OpenAI API key and determine its type/limits"""
    api_key = request.data.get('api_key', '').strip()
    
    if not api_key:
        return Response({"error": "API key required"}, status=400)
    
    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        # 1. Test basic authentication with models list
        models_response = requests.get(
            "https://api.openai.com/v1/models",
            headers=headers,
            timeout=10
        )
        
        if models_response.status_code != 200:
            return Response({
                "success": False,
                "error": f"Authentication failed: {models_response.status_code}",
                "details": models_response.json() if models_response.content else "Invalid key"
            }, status=400)
        
        # 2. Get available models
        models_data = models_response.json().get('data', [])
        available_models = [m['id'] for m in models_data]
        
        # 3. Check subscription/usage info
        subscription_response = requests.get(
            "https://api.openai.com/v1/dashboard/billing/subscription",
            headers=headers,
            timeout=10
        )
        
        key_type = 'unknown'
        has_credit = Decimal('0.00')
        models_access = []
        
        if subscription_response.status_code == 200:
            subscription_data = subscription_response.json()
            
            # Determine key type
            plan = subscription_data.get('plan', {}).get('id', '')
            hard_limit = subscription_data.get('hard_limit_usd', 0)
            
            if plan == 'free' or hard_limit == 0:
                key_type = 'free_tier'
                # Free tier usually has $0 or $5 credit
                has_credit = Decimal(str(subscription_data.get('system_hard_limit_usd', 0) or 0))
                
                # Free tier typically has access to:
                free_models = ['gpt-3.5-turbo', 'gpt-3.5-turbo-instruct', 
                              'babbage-002', 'davinci-002', 'text-embedding-ada-002']
                models_access = [m for m in free_models if any(fm in m for fm in available_models)]
                
            else:
                key_type = 'pay_as_you_go'
                has_credit = Decimal(str(hard_limit))
                
                # Check for GPT-4 access
                gpt4_models = [m for m in available_models if 'gpt-4' in m]
                gpt35_models = [m for m in available_models if 'gpt-3.5' in m]
                models_access = gpt35_models + gpt4_models
        
        # 4. Get usage data
        usage_response = requests.get(
            f"https://api.openai.com/v1/dashboard/billing/usage",
            headers=headers,
            timeout=10
        )
        
        usage_data = {}
        if usage_response.status_code == 200:
            usage_data = usage_response.json()
        
        # 5. Test actual API call with gpt-3.5-turbo
        test_prompt = "Hello, this is a test. Respond with 'OK' if you can read this."
        
        test_response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json={
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": test_prompt}],
                "max_tokens": 10,
                "temperature": 0
            },
            timeout=15
        )
        
        can_chat = test_response.status_code == 200
        
        return Response({
            "success": True,
            "message": "OpenAI API key is valid",
            "key_type": key_type,
            "credit_balance": float(has_credit),
            "has_gpt4_access": any('gpt-4' in m for m in available_models),
            "has_gpt35_access": any('gpt-3.5' in m for m in available_models),
            "available_models_count": len(available_models),
            "can_chat": can_chat,
            "models_access": models_access[:10],  # First 10 models
            "suggested_model": "gpt-3.5-turbo",
            "is_free_tier": key_type == 'free_tier',
            "free_tier_info": "Free tier gets limited GPT-3.5 access" if key_type == 'free_tier' else "Paid account",
            "usage": usage_data
        })
        
    except requests.exceptions.RequestException as e:
        return Response({
            "success": False,
            "error": f"Connection error: {str(e)}"
        }, status=500)