"""
Vercel Serverless Entry Point for AegisForensics
"""
import os
import sys

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app import AegisRequestHandler

# Vercel looks for a subclass of BaseHTTPRequestHandler named 'handler'
class handler(AegisRequestHandler):
    pass
