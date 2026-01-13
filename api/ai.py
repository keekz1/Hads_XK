# api/ai.py - COMPLETE WITH FREE GROQ
import redis
import hashlib
import json
import requests
from django.conf import settings
from decimal import Decimal
import time
import groq  # Groq Python SDK - don't import Groq directly
# Initialize Redis for caching (optional)
def get_redis_client():
    """Get Redis client with fallback"""
    try:
        if hasattr(settings, 'REDIS_URL'):
            redis_client = redis.Redis.from_url(
                settings.REDIS_URL,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True
            )
        else:
            redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True
            )
        
        redis_client.ping()
        print("✅ Redis connected successfully")
        return redis_client
    except (redis.ConnectionError, redis.TimeoutError) as e:
        print(f"⚠️ Redis not available: {e}. Caching disabled.")
        return None

redis_client = get_redis_client()

class ChatService:
    @staticmethod
    def get_cache_key(messages, model="", provider=""):
        """Generate cache key for messages"""
        if not messages:
            return "empty"
        
        # Use last 2 messages for cache key
        recent_msgs = messages[-2:] if len(messages) > 2 else messages
        content = json.dumps(recent_msgs, sort_keys=True) + model + provider
        return f"ai_cache:{hashlib.md5(content.encode()).hexdigest()}"
    
    @staticmethod
    def get_fallback_response(question):
        """Return cached responses for common questions"""
        fallbacks = {
            "hello": "Hi! I'm your study assistant. How can I help you learn today?",
            "hi": "Hello! Ready to study something new?",
            "hey": "Hey there! What would you like to learn about?",
            "thank you": "You're welcome! Keep up the great learning!",
            "thanks": "You're welcome! 😊",
            "help": "I can help you with studying, explaining concepts, answering questions, and more! Just ask me anything!",
            "what can you do": "I'm a study assistant! I can:\n• Explain concepts\n• Answer questions\n• Help with homework\n• Create study plans\n• Quiz you on topics\nWhat would you like help with?",
            "who are you": "I'm your AI study assistant, here to help you learn and understand various subjects. I can explain concepts, answer questions, and help you study more effectively!",
        }
        
        if not question:
            return None
            
        question_lower = question.lower().strip()
        for key, response in fallbacks.items():
            if key in question_lower:
                return response
        
        return None
 # Add this to your ai.py file

def analyze_document_with_ai(document_text, question="", api_key=None, provider="groq", model=None):
    """
    Analyze document content using AI
    
    Args:
        document_text: Text extracted from document
        question: Optional question to answer
        api_key: User's API key
        provider: AI provider ('groq', 'openai', etc.)
        model: Model to use
    
    Returns:
        dict with analysis results
    """
    # Limit document context to avoid token limits
    context = document_text[:6000] if len(document_text) > 6000 else document_text
    
    # Create system message
    system_message = """You are an expert document analyzer. Your task is to:
1. Provide accurate analysis based ONLY on the document content
2. If asked a specific question, answer based only on the document
3. If information isn't in the document, clearly state this
4. For general analysis, provide comprehensive breakdown
5. Be factual and avoid speculation"""
    
    # Create prompt
    if question:
        user_message = f"""Analyze this document and answer the question:

DOCUMENT:
{context}

QUESTION: {question}

Please provide a detailed answer based ONLY on the document. If the information isn't there, say so."""
    else:
        user_message = f"""Please analyze this document comprehensively:

DOCUMENT:
{context}

Provide a detailed analysis covering key points, themes, structure, and significance."""
    
    # Prepare conversation
    conversation = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message}
    ]
    
    try:
        # Use your existing ask_ai_with_provider function
        result = ask_ai_with_provider(
            api_key=api_key,
            provider=provider,
            messages=conversation,
            model=model or ("llama-3.1-8b-instant" if provider == "groq" else "gpt-3.5-turbo"),
            max_tokens=2500,
            temperature=0.3
        )
        
        return {
            "success": True,
            "analysis": result["answer"],
            "tokens_used": result["total_tokens"],
            "input_tokens": result["input_tokens"],
            "output_tokens": result["output_tokens"],
            "model": result.get("model", model),
            "provider": provider
        }
        
    except Exception as e:
        print(f"Document analysis error in ai.py: {e}")
        return {
            "success": False,
            "error": str(e),
            "analysis": None
        }   
@staticmethod
def calculate_cost(input_tokens, output_tokens, model="llama-3.1-8b-instant", provider="groq"):
    """
    Calculate estimated cost to USER
    FREE for Groq! $0.00
    """
    if provider == "groq":
        # GROQ IS FREE! 5M tokens/month
        return Decimal('0.0000')
    
    # Convert all prices to Decimal
    # OpenAI pricing per 1K tokens
    openai_pricing = {
        "gpt-4o-mini": {"input": Decimal('0.00015'), "output": Decimal('0.00060')},
        "gpt-4o": {"input": Decimal('0.0005'), "output": Decimal('0.0015')},
        "gpt-4-turbo": {"input": Decimal('0.01'), "output": Decimal('0.03')},
        "gpt-3.5-turbo": {"input": Decimal('0.0005'), "output": Decimal('0.0015')},
    }
    
    # Anthropic pricing
    anthropic_pricing = {
        "claude-3-haiku": {"input": Decimal('0.00025'), "output": Decimal('0.00125')},
        "claude-3-sonnet": {"input": Decimal('0.003'), "output": Decimal('0.015')},
    }
    
    # Google Gemini pricing
    gemini_pricing = {
        "gemini-pro": {"input": Decimal('0.000125'), "output": Decimal('0.000375')},
    }
    
    # Determine provider and pricing
    model_lower = model.lower()
    
    if provider == "openai":
        pricing = openai_pricing
    elif provider == "anthropic":
        pricing = anthropic_pricing
    elif provider == "gemini":
        pricing = gemini_pricing
    else:
        # Default to free (Groq)
        return Decimal('0.0000')
    
    # Get model pricing
    model_key = next((k for k in pricing.keys() if k in model_lower), list(pricing.keys())[0])
    model_pricing = pricing.get(model_key, list(pricing.values())[0])
    
    # Convert tokens to Decimal before calculation
    input_tokens_dec = Decimal(str(input_tokens))
    output_tokens_dec = Decimal(str(output_tokens))
    
    input_cost = (input_tokens_dec / Decimal('1000')) * model_pricing["input"]
    output_cost = (output_tokens_dec / Decimal('1000')) * model_pricing["output"]
    
    return input_cost + output_cost

def call_groq_api(api_key, messages, model="llama-3.1-8b-instant", max_tokens=2000, temperature=0.7):
    """
    Call Groq API with user's API key
    FREE! 5M tokens/month per user
    """
    try:
        # Initialize Groq client with USER'S key
        client = Groq(api_key=api_key)
        
        # Prepare messages for Groq
        # Groq doesn't have system messages, so prepend to first user message
        groq_messages = []
        for msg in messages:
            if msg["role"] == "system":
                # Add system message as part of first user message
                if groq_messages and groq_messages[-1]["role"] == "user":
                    groq_messages[-1]["content"] = f"{msg['content']}\n\n{groq_messages[-1]['content']}"
                else:
                    # Create a user message with system content
                    groq_messages.append({"role": "user", "content": msg["content"]})
            else:
                groq_messages.append(msg)
        
        # If no messages after processing, add a default
        if not groq_messages:
            groq_messages.append({"role": "user", "content": "Hello"})
        
        start_time = time.time()
        
        # Call Groq API (FREE!)
        completion = client.chat.completions.create(
            model=model,
            messages=groq_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=30
        )
        
        response_time = int((time.time() - start_time) * 1000)
        
        answer = completion.choices[0].message.content
        
        # Groq doesn't provide token counts in basic response
        # Estimate tokens: 1 token ≈ 4 characters
        estimated_tokens = len(answer) // 4
        
        return {
            "answer": answer,
            "input_tokens": estimated_tokens,  # Estimated
            "output_tokens": estimated_tokens,  # Estimated
            "total_tokens": estimated_tokens * 2,  # Estimated
            "response_time_ms": response_time,
            "estimated_tokens": True
        }
        
    except Exception as e:
        error_msg = str(e)
        if "rate limit" in error_msg.lower():
            raise Exception("Your Groq API key has reached its rate limit. Free tier: 5M tokens/month.")
        elif "invalid" in error_msg.lower() or "authentication" in error_msg.lower():
            raise Exception("Invalid Groq API key. Please check your key at https://console.groq.com/keys")
        else:
            raise Exception(f"Groq API error: {error_msg}")


def call_openai_api(api_key, messages, model="gpt-4o-mini", max_tokens=2000, temperature=0.7):
    """Call OpenAI API with user's API key (Paid)"""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False
    }
    
    start_time = time.time()
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=30
    )
    response_time = int((time.time() - start_time) * 1000)
    
    if response.status_code != 200:
        error_data = response.json()
        raise Exception(f"OpenAI API error: {error_data.get('error', {}).get('message', 'Unknown error')}")
    
    data = response.json()
    
    # Parse tokens
    usage = data.get("usage", {})
    input_tokens = usage.get("prompt_tokens", 0)
    output_tokens = usage.get("completion_tokens", 0)
    total_tokens = usage.get("total_tokens", 0)
    
    # Get response text
    answer = data["choices"][0]["message"]["content"]
    
    return {
        "answer": answer,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "response_time_ms": response_time
    }


def call_anthropic_api(api_key, messages, model="claude-3-haiku", max_tokens=2000):
    """Call Anthropic API with user's API key (Paid)"""
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json"
    }
    
    # Convert messages format for Anthropic
    anthropic_messages = []
    system_message = "You are a helpful AI assistant."
    
    for msg in messages:
        if msg["role"] == "system":
            system_message = msg["content"]
        else:
            anthropic_messages.append({
                "role": msg["role"],
                "content": msg["content"]
            })
    
    payload = {
        "model": model,
        "messages": anthropic_messages,
        "max_tokens": max_tokens,
        "system": system_message
    }
    
    start_time = time.time()
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers=headers,
        json=payload,
        timeout=30
    )
    response_time = int((time.time() - start_time) * 1000)
    
    if response.status_code != 200:
        error_data = response.json()
        raise Exception(f"Anthropic API error: {error_data.get('error', {}).get('message', 'Unknown error')}")
    
    data = response.json()
    
    # Parse tokens (Anthropic format)
    usage = data.get("usage", {})
    input_tokens = usage.get("input_tokens", 0)
    output_tokens = usage.get("output_tokens", 0)
    total_tokens = input_tokens + output_tokens
    
    # Get response text
    answer = data["content"][0]["text"]
    
    return {
        "answer": answer,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "response_time_ms": response_time
    }


def call_gemini_api(api_key, messages, model="gemini-pro", max_tokens=2000, temperature=0.7):
    """Call Google Gemini API with user's API key (Paid)"""
    headers = {
        "Content-Type": "application/json"
    }
    
    # Gemini API format is different
    system_message = "You are a helpful AI assistant."
    gemini_contents = []
    
    for msg in messages:
        if msg["role"] == "system":
            system_message = msg["content"]
        else:
            gemini_contents.append({
                "role": "user" if msg["role"] == "user" else "model",
                "parts": [{"text": msg["content"]}]
            })
    
    # Gemini requires the model name in the URL
    url = f"https://generativelanguage.googleapis.com/v1/models/{model}:generateContent"
    
    params = {"key": api_key}
    
    payload = {
        "contents": gemini_contents,
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": temperature
        }
    }
    
    start_time = time.time()
    response = requests.post(
        url,
        headers=headers,
        params=params,
        json=payload,
        timeout=30
    )
    response_time = int((time.time() - start_time) * 1000)
    
    if response.status_code != 200:
        error_data = response.json()
        raise Exception(f"Gemini API error: {error_data.get('error', {}).get('message', 'Unknown error')}")
    
    data = response.json()
    
    # Gemini doesn't provide token counts in basic API
    answer = data["candidates"][0]["content"]["parts"][0]["text"]
    estimated_tokens = len(answer) // 4
    
    return {
        "answer": answer,
        "input_tokens": estimated_tokens,  # Estimated
        "output_tokens": estimated_tokens,  # Estimated
        "total_tokens": estimated_tokens * 2,  # Estimated
        "response_time_ms": response_time,
        "estimated_tokens": True
    }


def ask_ai_with_provider(api_key, provider, messages, model=None, **kwargs):
    """Route API call to appropriate provider"""
    # Set default model based on provider
    if not model:
        if provider == "groq":
            model = "llama-3.1-8b-instant"  # FREE Groq model
        elif provider == "openai":
            model = "gpt-4o-mini"
        elif provider == "anthropic":
            model = "claude-3-haiku"
        elif provider == "gemini":
            model = "gemini-pro"
        else:
            model = "llama-3.1-8b-instant"  # Default to FREE Groq
    
    try:
        if provider == "groq":
            result = call_groq_api(api_key, messages, model, **kwargs)
        elif provider == "openai":
            result = call_openai_api(api_key, messages, model, **kwargs)
        elif provider == "anthropic":
            result = call_anthropic_api(api_key, messages, model, **kwargs)
        elif provider == "gemini":
            result = call_gemini_api(api_key, messages, model, **kwargs)
        else:
            raise ValueError(f"Unsupported provider: {provider}")
        
        # Add provider info to result
        result["provider"] = provider
        result["model"] = model
        
        return result
        
    except requests.exceptions.Timeout:
        raise Exception(f"{provider.capitalize()} API timeout - please try again")
    except Exception as e:
        # Re-raise with provider context
        raise Exception(f"{provider.capitalize()} API error: {str(e)}")


def ask_ai(user_id, conversation, subject=None, difficulty=None, 
           provider="groq", api_key=None, model=None):
    """
    Main AI function - PROXY to user's chosen provider
    Default: FREE Groq!
    """
    
    if not conversation or not isinstance(conversation, list):
        conversation = []
    
    # Get last user message
    last_user_msg = next(
        (msg.get("content") for msg in reversed(conversation) if msg.get("role") == "user"),
        ""
    )
    
    # 1. Check fallback responses (always free)
    fallback = ChatService.get_fallback_response(last_user_msg)
    if fallback:
        return {
            "answer": fallback,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "response_time_ms": 0,
            "cached": True,
            "fallback": True,
            "provider": "fallback",
            "estimated_user_cost": Decimal('0.0000'),
            "your_service_fee": Decimal('0.0001'),
            "is_free": True
        }
    
    # 2. Check Redis cache (if available)
    cache_key = None
    if redis_client and api_key:
        try:
            cache_key = ChatService.get_cache_key(conversation, model or "", provider)
            cached_response = redis_client.get(cache_key)
            if cached_response:
                print(f"✅ Cache HIT for: {last_user_msg[:50]}...")
                return {
                    "answer": cached_response,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "response_time_ms": 0,
                    "cached": True,
                    "cache_key": cache_key[:20],
                    "provider": provider,
                    "estimated_user_cost": Decimal('0.0000'),
                    "your_service_fee": Decimal('0.0001'),
                    "is_free": provider == 'groq'
                }
            else:
                print(f"🔍 Cache MISS for: {last_user_msg[:50]}...")
        except Exception as e:
            print(f"⚠️ Redis cache error (will continue): {e}")
    
    # 3. Prepare system message
    if subject and difficulty:
        system_message = f"You are a helpful study assistant specializing in {subject} at {difficulty} level."
    elif subject:
        system_message = f"You are a helpful study assistant for {subject}."
    else:
        system_message = "You are a helpful study assistant."
    
    # Prepare messages for API
    messages_for_api = [{"role": "system", "content": system_message}] + conversation[-5:]
    
    # 4. Call API with user's key
    if not api_key:
        raise ValueError(f"API key required for {provider}. Please set up your {provider} API key.")
    
    try:
        print(f"📤 Calling {provider.upper()} API: {last_user_msg[:50]}...")
        
        result = ask_ai_with_provider(
            api_key=api_key,
            provider=provider,
            messages=messages_for_api,
            model=model,
            max_tokens=2000,
            temperature=0.7
        )
        
        print(f"📥 Received response from {provider}: {result['answer'][:50]}...")
        
        # 5. Save to Redis cache (if available)
        if redis_client and cache_key and not result.get("estimated_tokens", False):
            try:
                # Cache for 1 hour (3600 seconds)
                redis_client.setex(cache_key, 3600, result["answer"])
                print(f"💾 Saved to cache: {cache_key[:20]}...")
            except Exception as e:
                print(f"⚠️ Failed to save to cache: {e}")
        
        # Calculate estimated cost to USER (FREE for Groq!)
        result["estimated_user_cost"] = ChatService.calculate_cost(
            result["input_tokens"],
            result["output_tokens"],
            result["model"],
            provider
        )
        
        # YOUR service fee (tiny profit)
        result["your_service_fee"] = Decimal('0.0001')
        
        # Mark if FREE (Groq)
        result["is_free"] = provider == 'groq'
        
        return result
        
    except Exception as e:
        error_msg = str(e)
        print(f"❌ {provider.upper()} API Error: {error_msg[:100]}")
        
        # User-friendly error messages
        if "rate limit" in error_msg.lower() or "quota" in error_msg.lower():
            raise Exception(f"Your {provider} API key has reached its limit. Groq: 5M tokens/month free.")
        elif "invalid" in error_msg.lower() or "authentication" in error_msg.lower():
            raise Exception(f"Invalid {provider} API key. Please check your API key.")
        elif "timeout" in error_msg.lower():
            raise Exception("The request took too long. Please try again with a shorter question.")
        else:
            raise Exception(f"{provider.capitalize()} API error: {error_msg[:100]}")


# Backward compatibility wrapper
def ask_ai_old(prompt):
    """Legacy function for backward compatibility"""
    conversation = [{"role": "user", "content": prompt}]
    try:
        # Try to use a default/test key from settings
        from django.conf import settings
        
        # Check for a test API key in settings
        test_api_key = getattr(settings, 'TEST_GROQ_API_KEY', None)
        if test_api_key:
            result = ask_ai(
                user_id=1,
                conversation=conversation,
                provider="groq",
                api_key=test_api_key,
                model="llama-3.1-8b-instant"
            )
            return result["answer"]
        else:
            # Fallback
            return "API key not configured. Please set up your Groq API key (FREE at groq.com)."
    except Exception as e:
        return f"Error: {str(e)[:100]}"


# Utility function for views to use
def proxy_ai_request(user, prompt, subject=None, difficulty=None, model=None):
    """
    Convenience function for views to make AI requests
    Default: FREE Groq!
    """
    try:
        profile = user.userprofile
        api_key = profile.get_api_key()
        provider = profile.preferred_provider
        
        if not api_key:
            return {
                "success": False,
                "error": "API key not configured",
                "requires_setup": True,
                "provider": provider,
                "is_groq": provider == 'groq'
            }
        
        conversation = [{"role": "user", "content": prompt}]
        
        result = ask_ai(
            user_id=user.id,
            conversation=conversation,
            subject=subject,
            difficulty=difficulty,
            provider=provider,
            api_key=api_key,
            model=model or profile.preferred_model
        )
        
        result["success"] = True
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "requires_setup": "invalid" in str(e).lower() or "key" in str(e).lower(),
            "provider": getattr(profile, 'preferred_provider', 'groq'),
            "is_groq": getattr(profile, 'preferred_provider', 'groq') == 'groq'
        }


# Test function for development
def test_api_connection(api_key, provider="groq"):
    """Test if API key works"""
    try:
        test_messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say 'Connection test successful' if you can read this."}
        ]
        
        result = ask_ai_with_provider(
            api_key=api_key,
            provider=provider,
            messages=test_messages,
            max_tokens=10
        )
        
        return {
            "success": True,
            "provider": provider,
            "message": result["answer"],
            "tokens_used": result["total_tokens"],
            "is_free": provider == 'groq'
        }
    except Exception as e:
        return {
            "success": False,
            "provider": provider,
            "error": str(e),
            "is_free": provider == 'groq'
        }


# Groq-specific helper
def get_groq_setup_instructions(user_email):
    """
    Generate setup instructions for FREE Groq
    """
    referral_id = f"studypilot_{int(time.time())}"
    
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
    
    return {
        "success": True,
        "provider": "groq",
        "is_free": True,
        "free_tokens": "5,000,000 tokens/month",
        "instructions": instructions,
        "signup_url": "https://console.groq.com/signup",
        "api_keys_url": "https://console.groq.com/keys",
        "referral_id": referral_id
    }