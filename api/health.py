# api/health.py
from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(['GET'])
def health_check(request):
    return Response({
        "status": "healthy", 
        "service": "studypilot-backend",
        "version": "1.0.0"
    })