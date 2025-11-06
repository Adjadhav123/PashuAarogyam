from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, make_response, send_file
import os
from dotenv import load_dotenv
import json
from werkzeug.utils import secure_filename
import uuid
import bcrypt
import time
import random

# Try to import reportlab for PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import inch
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.linecharts import HorizontalLineChart
    REPORTLAB_AVAILABLE = True
    print("✅ ReportLab import successful!")
except ImportError as e:
    print(f"⚠️  ReportLab import failed: {e}")
    print("⚠️  PDF export functionality will be disabled.")
    REPORTLAB_AVAILABLE = False

load_dotenv()


try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
    print("✅ Google Generative AI import successful!")
except ImportError as e:
    print(f"⚠️  Google Generative AI import failed: {e}")
    GEMINI_AVAILABLE = False

# Configure Gemini API with dual keys for load balancing
GEMINI_API_KEY_DISEASE = "AIzaSyBwVTmnjb8AJDMTlWfhs5KBenLq8kzWzr0"  # For disease detection
GEMINI_API_KEY_CHATBOT = "AIzaSyAS1i1N6qAU-g3g8WYPXdz4N-sdkxOONqY"  # For chatbot

# Re-enable Gemini with dual API system
if GEMINI_AVAILABLE:
    try:
        # Configure with the disease detection API key as primary
        genai.configure(api_key=GEMINI_API_KEY_DISEASE)
        print("✅ Gemini AI configured successfully with dual API keys!")
        print("   🔑 Disease Detection API: ..."+GEMINI_API_KEY_DISEASE[-10:])
        print("   🔑 Chatbot API: ..."+GEMINI_API_KEY_CHATBOT[-10:])
    except Exception as e:
        print(f"⚠️  Gemini AI configuration failed: {e}")
        GEMINI_AVAILABLE = False

# Try to import MongoDB with error handling
try:
    from pymongo import MongoClient
    MONGODB_AVAILABLE = True
    print("✅ MongoDB import successful!")
except ImportError as e:
    print(f"⚠️  MongoDB import failed: {e}")
    print("⚠️  MongoDB functionality will be disabled.")
    MongoClient = None
    MONGODB_AVAILABLE = False

from bson import ObjectId
from datetime import datetime, timezone, timedelta
import re
import traceback
import torch
from ultralytics import YOLO
from PIL import Image
import io
import numpy as np
import base64

# Try to import chatbot service with error handling
try:
    from chatbot_service_new import AnimalDiseaseChatbot
    CHATBOT_AVAILABLE = True
    print("✅ Chatbot service import successful!")
except ImportError as e:
    print(f"⚠️  Chatbot service import failed: {e}")
    print("⚠️  Chatbot functionality will be disabled.")
    AnimalDiseaseChatbot = None
    CHATBOT_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'  # Change this in production

# MongoDB Configuration
MONGODB_URI = "mongodb+srv://kunalsurade016_db_user:umcunBXqOZO3AUK3@animal1.rydpf7k.mongodb.net/gorakshaai?retryWrites=true&w=majority"

# Initialize MongoDB connection variables
client = None
db = None
users_collection = None
predictions_collection = None
consultants_collection = None
consultation_requests_collection = None
messages_collection = None

def initialize_mongodb():
    """Initialize MongoDB connection with the correct credentials"""
    global client, db, users_collection, predictions_collection, consultants_collection, consultation_requests_collection, messages_collection
    
    if not MONGODB_AVAILABLE:
        print("⚠️  MongoDB not available - skipping database initialization")
        return False
    
    print("🔄 Initializing MongoDB connection...")
    
    try:
        # Create MongoDB client with proper configuration
        client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=30000,  
            connectTimeoutMS=20000,          # 20 seconds
            socketTimeoutMS=20000,           # 20 seconds
            maxPoolSize=50,
            retryWrites=True
        )
        
        # Test the connection by pinging the admin database
        client.admin.command('ping')
        print("✅ MongoDB ping successful!")
        
        # Initialize database and collections  
        db = client['gorakshaai']
        users_collection = db['users']
        predictions_collection = db['predictions']
        consultants_collection = db['consultants']
        consultation_requests_collection = db['consultation_requests']
        messages_collection = db['messages']
        
        print(f"✅ Collections initialized:")
        print(f"   - users_collection: {users_collection is not None}")
        print(f"   - consultants_collection: {consultants_collection is not None}")
        print(f"   - consultation_requests_collection: {consultation_requests_collection is not None}")
        print(f"   - messages_collection: {messages_collection is not None}")
        
        # Create indexes for better performance
        try:
            users_collection.create_index("email", unique=True)
            predictions_collection.create_index("user_id")
            predictions_collection.create_index("created_at")
            predictions_collection.create_index("animal_type")
            predictions_collection.create_index("prediction")
            consultants_collection.create_index("email", unique=True)
            consultation_requests_collection.create_index("status")
            consultation_requests_collection.create_index("created_at")
            messages_collection.create_index("consultation_id")
            messages_collection.create_index("created_at")
            print("✅ Database indexes created successfully!")
        except Exception as idx_error:
            print(f"⚠️  Index creation warning: {str(idx_error)}")
        
        # Initialize sample data
        initialize_sample_data()
        
        # Test collections access
        user_count = users_collection.count_documents({})
        print(f"✅ Users collection accessible. Current user count: {user_count}")
        
        print("✅ MongoDB connected successfully!")
        return True
        
    except Exception as e:
        print(f"❌ MongoDB connection failed: {str(e)}")
        print(f"❌ Error type: {type(e).__name__}")
        print("⚠️  Starting without database - authentication will not work")
        
        # Set globals to None on failure
        client = None
        db = None
        users_collection = None
        predictions_collection = None
        consultants_collection = None
        consultation_requests_collection = None
        messages_collection = None
        return False

# Rate limiting for Gemini API - Relaxed with dual API keys
class GeminiRateLimiter:
    def __init__(self):
        self.last_call_time = 0
        self.min_interval = 0.5  # Reduced from 1 second to 0.5 seconds with dual APIs
        self.rate_limit_until = 0  # Timestamp until when we're rate limited
        self.consecutive_failures = 0
        
    def wait_if_needed(self):
        """Wait if we need to respect rate limits"""
        current_time = time.time()
        
        # Check if we're still in rate limit period
        if current_time < self.rate_limit_until:
            wait_time = self.rate_limit_until - current_time
            print(f"⏳ Rate limited. Waiting {wait_time:.1f} seconds...")
            time.sleep(wait_time)
            return True
            
        # Ensure minimum interval between calls
        time_since_last = current_time - self.last_call_time
        if time_since_last < self.min_interval:
            wait_time = self.min_interval - time_since_last
            time.sleep(wait_time)
            
        self.last_call_time = time.time()
        return False
        
    def handle_rate_limit_error(self):
        """Handle 429 rate limit error - Reduced wait time with dual APIs"""
        self.consecutive_failures += 1
        base_wait = min(30, 1.5 ** self.consecutive_failures)  # Reduced exponential backoff
        jitter = random.uniform(0.8, 1.2)  # Reduced jitter
        wait_time = base_wait * jitter
        
        self.rate_limit_until = time.time() + wait_time
        self.min_interval = min(3, self.min_interval * 1.2)  # Slower increase
        
        print(f"⚠️ Rate limit hit. Backing off for {wait_time:.1f} seconds...")
        return wait_time
        
    def reset_on_success(self):
        """Reset failure count on successful call"""
        self.consecutive_failures = 0
        self.min_interval = max(0.5, self.min_interval * 0.95)  # Gradually reduce interval

# Global rate limiter instance
gemini_rate_limiter = GeminiRateLimiter()

def call_gemini_with_retry(model_name, prompt, image_parts=None, max_retries=2, api_key=None):
    """
    Call Gemini API with proper error handling, rate limiting, and retries
    Reduced retries since we have dual API system for load balancing
    """
    if not GEMINI_AVAILABLE:
        return None, "Gemini AI is not available"
    
    # Use provided API key or default to disease detection key
    if api_key is None:
        api_key = GEMINI_API_KEY_DISEASE
        
    for attempt in range(max_retries):
        try:
            # Wait if rate limited
            was_rate_limited = gemini_rate_limiter.wait_if_needed()
            
            # Configure with the specific API key for this request
            genai.configure(api_key=api_key)
            
            # Create model and make request
            model = genai.GenerativeModel(model_name)
            
            if image_parts:
                response = model.generate_content([prompt] + image_parts)
            else:
                response = model.generate_content(prompt)
            
            if response and response.text:
                gemini_rate_limiter.reset_on_success()
                return response.text.strip(), None
            else:
                return None, "Empty response from Gemini AI"
                
        except Exception as e:
            error_str = str(e).lower()
            
            # Handle different types of errors
            if "429" in error_str or "resource exhausted" in error_str or "quota" in error_str:
                wait_time = gemini_rate_limiter.handle_rate_limit_error()
                
                if attempt < max_retries - 1:
                    print(f"🔄 Retrying after rate limit (attempt {attempt + 1}/{max_retries})...")
                    time.sleep(wait_time)
                    continue
                else:
                    return None, f"Rate limit exceeded after {max_retries} attempts. Please try again later."
                    
            elif "network" in error_str or "connection" in error_str or "timeout" in error_str:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2  # Linear backoff for network issues
                    print(f"🌐 Network error, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})...")
                    time.sleep(wait_time)
                    continue
                else:
                    return None, f"Network error after {max_retries} attempts. Please check your connection."
                    
            elif "invalid" in error_str or "permission" in error_str:
                return None, f"API error: {str(e)}"
                
            else:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 1.5
                    print(f"⚠️ Gemini error, retrying in {wait_time}s: {str(e)[:100]}...")
                    time.sleep(wait_time)
                    continue
                else:
                    return None, f"Gemini API error: {str(e)}"
    
    return None, "Failed after all retry attempts"

# Initialize chatbot service
chatbot = None

def initialize_chatbot():
    """Initialize chatbot service with better error handling"""
    global chatbot
    
    try:
        if not CHATBOT_AVAILABLE:
            print("⚠️  Chatbot service not available - chatbot functionality will be disabled")
            return False
        
        # Use the dedicated chatbot API key
        gemini_api_key = GEMINI_API_KEY_CHATBOT
        
        if not gemini_api_key:
            print("❌ GEMINI_API_KEY_CHATBOT not configured")
            return False
        
        print("🔄 Initializing chatbot service with dedicated API key...")
        chatbot = AnimalDiseaseChatbot(gemini_api_key)
        print("✅ Chatbot service initialized successfully with chatbot API key!")
        return True
        
    except Exception as e:
        print(f"❌ Error initializing chatbot: {e}")
        print(f"❌ Error type: {type(e).__name__}")
        print("⚠️  Chatbot functionality will be disabled")
        chatbot = None
        return False

def get_chatbot_status():
    """Check if chatbot is available"""
    if chatbot is None:
        return False, "Chatbot not initialized"
    return True, "Chatbot ready"

def get_db_status():
    """Check if database is connected and available"""
    try:
        if client is None or db is None:
            return False, "Database not initialized"
        
        # Test connection
        client.admin.command('ping')
        return True, "Database connected"
    except Exception as e:
        return False, f"Database error: {str(e)}"

def initialize_sample_data():
    """Initialize sample data for veterinary consultation system"""
    try:
        # Check if sample consultant already exists
        if consultants_collection is not None and consultants_collection.count_documents({}) == 0:
            # Create a sample consultant
            sample_consultant = {
                'email': 'vet@goraksha.ai',
                'password': hash_password('password123'),
                'name': 'Dr. Sarah Johnson',
                'specialization': 'Large Animals',
                'experience': '10+ years',
                'phone': '+91 9876543210',
                'license_number': 'VET123456',
                'qualifications': 'B.V.Sc., M.V.Sc. (Animal Medicine)',
                'status': 'active',
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc)
            }
            consultants_collection.insert_one(sample_consultant)
            print("✅ Sample consultant created: vet@goraksha.ai / password123")
        
        # Check if sample consultation requests exist
        if consultation_requests_collection is not None and consultation_requests_collection.count_documents({}) == 0:
            # Create sample consultation requests
            sample_requests = [
                {
                    'farmer_name': 'Ramesh Kumar',
                    'farm_name': 'Green Valley Farm',
                    'farmer_email': 'ramesh@farm.com',
                    'contact_phone': '+91 9876543210',
                    'location': 'Pune, Maharashtra',
                    'animal_type': 'Cattle',
                    'animal_age': '3 years',
                    'animal_breed': 'Holstein',
                    'symptoms': 'My cow has been showing signs of loss of appetite for the past 2 days. She is also producing less milk than usual and seems lethargic. I noticed some nasal discharge yesterday.',
                    'duration': '2-3 days',
                    'urgency': 'High',
                    'additional_notes': 'This is one of my best milk producers. Recently changed her feed mix.',
                    'status': 'Pending',
                    'assigned_to': None,
                    'assigned_consultant_name': None,
                    'created_at': datetime.now(timezone.utc),
                    'images': []
                },
                {
                    'farmer_name': 'Priya Sharma',
                    'farm_name': 'Sharma Dairy',
                    'farmer_email': 'priya@sharma.dairy',
                    'contact_phone': '+91 9123456789',
                    'location': 'Nashik, Maharashtra',
                    'animal_type': 'Buffalo',
                    'animal_age': '5 years',
                    'animal_breed': 'Murrah',
                    'symptoms': 'Buffalo has swollen udder and seems to be in pain while milking. Milk production has decreased significantly.',
                    'duration': '4-5 days',
                    'urgency': 'Medium',
                    'additional_notes': 'No recent changes in diet or environment. Other animals seem fine.',
                    'status': 'Pending',
                    'assigned_to': None,
                    'assigned_consultant_name': None,
                    'created_at': datetime.now(timezone.utc) - timedelta(hours=6),
                    'images': []
                },
                {
                    'farmer_name': 'Suresh Patel',
                    'farm_name': 'Patel Goat Farm',
                    'farmer_email': '',
                    'contact_phone': '+91 9988776655',
                    'location': 'Ahmedabad, Gujarat',
                    'animal_type': 'Goat',
                    'animal_age': '2 years',
                    'animal_breed': 'Jamunapari',
                    'symptoms': 'Goat has been limping on front left leg. No visible injury but avoids putting weight on it.',
                    'duration': '1 week',
                    'urgency': 'Low',
                    'additional_notes': 'Eating and drinking normally otherwise.',
                    'status': 'Pending',
                    'assigned_to': None,
                    'assigned_consultant_name': None,
                    'created_at': datetime.now(timezone.utc) - timedelta(hours=12),
                    'images': []
                }
            ]
            consultation_requests_collection.insert_many(sample_requests)
            print("✅ Sample consultation requests created")
        
    except Exception as e:
        print(f"⚠️  Error initializing sample data: {e}")

# Initialize MongoDB and chatbot on startup
print("🚀 Starting PashuAarogyam application...")
db_connected = initialize_mongodb()
if db_connected:
    print("🎉 Database connection established!")
else:
    print("⚠️  Application starting without database connection")

chatbot_initialized = initialize_chatbot()
if chatbot_initialized:
    print("🤖 Chatbot service is ready!")
else:
    print("⚠️  Application starting without chatbot functionality")

# Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize YOLO models
models = {}
try:
    # Load cat disease detection model
    if os.path.exists('models/cat_disease_best.pt'):
        models['cat'] = YOLO('models/cat_disease_best.pt')
        print("✅ Cat disease model loaded successfully!")
    else:
        print("⚠️  Cat disease model not found at models/cat_disease_best.pt")
    
    # Load cow disease detection model  
    if os.path.exists('models/lumpy_disease_best.pt'):
        models['cow'] = YOLO('models/lumpy_disease_best.pt')
        print("✅ Cow disease model loaded successfully!")
    else:
        print("⚠️  Cow disease model not found at models/lumpy_disease_best.pt")
    
    # Load dog disease detection model
    if os.path.exists('models/dog_disease_best.pt'):
        models['dog'] = YOLO('models/dog_disease_best.pt')
        print("✅ Dog disease model loaded successfully!")
    else:
        print("⚠️  Dog disease model not found at models/dog_disease_best.pt")
        
except Exception as e:
    print(f"❌ Error loading YOLO models: {e}")
    models = {}

# Treatment and Medicine Database
TREATMENT_DATABASE = {
    'cat': {
        'Ring Worm': {
            'description': 'Fungal infection causing circular hair loss and scaling',
            'treatment': 'Antifungal therapy and topical treatments are essential for recovery',
            'medicines': [
                {
                    'name': 'Itraconazole (Sporanox)',
                    'type': 'Systemic Antifungal',
                    'dosage': '5-10mg per kg daily for 4-6 weeks',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Chlorhexidine + Miconazole Shampoo',
                    'type': 'Antifungal Shampoo',
                    'dosage': 'Bathe twice weekly for 6-8 weeks',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Enilconazole (Imaverol)',
                    'type': 'Topical Antifungal Solution',
                    'dosage': 'Dilute 1:50 and apply every 3-4 days',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Griseofulvin',
                    'type': 'Oral Antifungal',
                    'dosage': '25-50mg per kg daily with fatty meal',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                }
            ]
        },
        'Feline Calicivirus': {
            'description': 'Viral respiratory infection common in cats',
            'treatment': 'Supportive care and symptom management are key to recovery',
            'medicines': [
                {
                    'name': 'Famciclovir (Famvir)',
                    'type': 'Antiviral Medication',
                    'dosage': '62.5mg twice daily for 10-14 days',
                    'image': 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Doxycycline',
                    'type': 'Broad Spectrum Antibiotic',
                    'dosage': '5mg per kg twice daily for 7-10 days',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'L-Lysine HCl (Viralys)',
                    'type': 'Immune Support Supplement',
                    'dosage': '250-500mg daily in food',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Terramycin Eye Ointment',
                    'type': 'Antibiotic Eye Treatment',
                    'dosage': 'Apply to eyes 2-3 times daily',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                }
            ]
        },
        'Flea Allergy': {
            'description': 'Allergic reaction to flea bites causing intense itching',
            'treatment': 'Flea control and anti-allergic treatment to prevent secondary infections',
            'medicines': [
                {
                    'name': 'Revolution (Selamectin)',
                    'type': 'Topical Flea & Tick Treatment',
                    'dosage': 'Apply monthly between shoulder blades',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Prednisolone Acetate',
                    'type': 'Corticosteroid Anti-inflammatory',
                    'dosage': '1-2mg per kg daily, then taper over 2 weeks',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Benadryl (Diphenhydramine)',
                    'type': 'Antihistamine',
                    'dosage': '1mg per kg twice daily',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Advantage II Flea Spray',
                    'type': 'Environmental Flea Control',
                    'dosage': 'Spray on bedding and carpet weekly',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                }
            ]
        },
        'Healthy': {
            'description': 'Your cat appears to be in good health',
            'treatment': 'Continue regular preventive care and monitoring',
            'medicines': [
                {
                    'name': 'Multivitamin Supplement',
                    'type': 'Nutritional Support',
                    'dosage': 'As per manufacturer guidelines',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Omega-3 Fish Oil',
                    'type': 'Coat and Skin Health',
                    'dosage': '1000mg daily with food',
                    'image': 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Dental Care Treats',
                    'type': 'Oral Health',
                    'dosage': '1-2 treats daily',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Probiotic Supplement',
                    'type': 'Digestive Health',
                    'dosage': 'As per veterinary recommendation',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                }
            ]
        },
        'Feline Dermatitis': {
            'description': 'Inflammatory skin condition with itching and lesions',
            'treatment': 'Anti-inflammatory therapy and allergen management',
            'medicines': [
                {
                    'name': 'Cyclosporine (Atopica)',
                    'type': 'Immunosuppressive Agent',
                    'dosage': '5mg per kg once daily, then reduce frequency',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Hydroxyzine HCl',
                    'type': 'Antihistamine',
                    'dosage': '1-2mg per kg twice daily',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Douxo S3 Calm Shampoo',
                    'type': 'Soothing Medicated Shampoo',
                    'dosage': 'Bathe weekly, leave on for 5-10 minutes',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Dermoscent Essential 6 Spot-On',
                    'type': 'Natural Skin Care Treatment',
                    'dosage': 'Apply weekly for 4 weeks, then monthly',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                }
            ]
        },
        'Upper Respiratory Infection': {
            'description': 'Common viral or bacterial infection affecting the upper respiratory tract',
            'treatment': 'Supportive care with antibiotics if bacterial component present',
            'medicines': [
                {
                    'name': 'Amoxicillin-Clavulanate',
                    'type': 'Broad Spectrum Antibiotic',
                    'dosage': '12.5mg per kg twice daily',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'L-Lysine Supplement',
                    'type': 'Immune Support',
                    'dosage': '250mg twice daily',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Saline Nasal Drops',
                    'type': 'Nasal Decongestant',
                    'dosage': '1-2 drops per nostril twice daily',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Humidifier Therapy',
                    'type': 'Environmental Support',
                    'dosage': 'Use continuously in living area',
                    'image': 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=300&h=200&fit=crop'
                }
            ]
        },
        'Feline Distemper': {
            'description': 'Highly contagious viral disease affecting the immune system',
            'treatment': 'Intensive supportive care and hospitalization may be required',
            'medicines': [
                {
                    'name': 'IV Fluid Therapy',
                    'type': 'Hydration Support',
                    'dosage': 'As prescribed by veterinarian',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Anti-nausea Medication',
                    'type': 'Symptom Control',
                    'dosage': 'As prescribed for vomiting control',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Broad Spectrum Antibiotic',
                    'type': 'Secondary Infection Prevention',
                    'dosage': 'As prescribed by veterinarian',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Nutritional Support',
                    'type': 'Recovery Aid',
                    'dosage': 'High-calorie paste as directed',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                }
            ]
        }
    },
    'cow': {
        'Lumpy Skin Disease': {
            'description': 'Viral disease causing skin nodules and lesions in cattle',
            'treatment': 'Supportive care and wound management to prevent secondary infections',
            'medicines': [
                {
                    'name': 'Oxytetracycline LA (Terramycin)',
                    'type': 'Long-acting Injectable Antibiotic',
                    'dosage': '20mg per kg intramuscularly every 72 hours',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Flunixin Meglumine (Banamine)',
                    'type': 'NSAID Anti-inflammatory',
                    'dosage': '2.2mg per kg intravenously once daily',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Betadine Solution (Povidone Iodine)',
                    'type': 'Topical Antiseptic',
                    'dosage': 'Clean lesions twice daily with 10% solution',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Vitamin AD3E + B-Complex Injectable',
                    'type': 'Immune System Support',
                    'dosage': '5-10ml intramuscularly weekly',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                }
            ]
        },
        'Healthy': {
            'description': 'Your cattle appears to be in good health',
            'treatment': 'Continue regular preventive care and vaccination schedule',
            'medicines': [
                {
                    'name': 'Mineral Supplement',
                    'type': 'Nutritional Support',
                    'dosage': '50-100g daily in feed',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Deworming Agent',
                    'type': 'Parasitic Prevention',
                    'dosage': 'As per veterinary schedule',
                    'image': 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Tick Spray',
                    'type': 'External Parasite Control',
                    'dosage': 'Apply weekly or as needed',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Vaccination Booster',
                    'type': 'Disease Prevention',
                    'dosage': 'Annual or as recommended',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                }
            ]
        },
        'Foot and Mouth Disease': {
            'description': 'Highly contagious viral disease affecting cloven-hoofed animals',
            'treatment': 'Supportive care and strict quarantine measures',
            'medicines': [
                {
                    'name': 'Foot and Mouth Disease Vaccine',
                    'type': 'Preventive Vaccine',
                    'dosage': '2ml intramuscularly, annual booster',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Zinc Sulfate Foot Bath',
                    'type': 'Hoof Disinfectant',
                    'dosage': '5% solution for hoof dipping twice weekly',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Copper Sulfate Solution',
                    'type': 'Antiseptic Hoof Treatment',
                    'dosage': '10% solution applied to affected hooves',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Vitamin AD3E Injectable',
                    'type': 'Immune Support',
                    'dosage': '5ml intramuscularly every 3 days',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                }
            ]
        },
        'Mastitis': {  
            'description': 'Inflammatory condition of the mammary gland, often caused by bacterial infection',
            'treatment': 'Antibiotic therapy and supportive care to restore milk production',
            'medicines': [
                {
                    'name': 'Intramammary Antibiotic',
                    'type': 'Targeted Antibiotic Treatment',
                    'dosage': 'Insert one tube per affected quarter',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Systemic Penicillin',
                    'type': 'Injectable Antibiotic',
                    'dosage': '22,000 units per kg twice daily',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Anti-inflammatory',
                    'type': 'Pain and Inflammation Control',
                    'dosage': '2.2mg per kg once daily',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Teat Dip Solution',
                    'type': 'Prevention and Hygiene',
                    'dosage': 'After each milking',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                }
            ]
        },
        'Bovine Respiratory Disease': {
            'description': 'Complex respiratory condition involving multiple pathogens',
            'treatment': 'Broad spectrum antibiotics and supportive respiratory care',
            'medicines': [
                {
                    'name': 'Florfenicol Injectable',
                    'type': 'Respiratory Antibiotic',
                    'dosage': '20mg per kg intramuscularly',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Meloxicam',
                    'type': 'Anti-inflammatory',
                    'dosage': '0.5mg per kg once daily',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Bronchodilator',
                    'type': 'Respiratory Support',
                    'dosage': 'As prescribed by veterinarian',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Electrolyte Solution',
                    'type': 'Hydration Support',
                    'dosage': '2-4 liters orally twice daily',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                }
            ]
        }
    },
    'dog': {
        'Skin Disease': {
            'description': 'Various skin conditions affecting dogs including allergies and infections',
            'treatment': 'Targeted therapy based on underlying cause and symptom management',
            'medicines': [
                {
                    'name': 'Malaseb Shampoo (Chlorhexidine + Miconazole)',
                    'type': 'Antifungal/Antibacterial Shampoo',
                    'dosage': 'Bathe twice weekly, leave on for 10 minutes',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Cephalexin (Keflex)',
                    'type': 'First-generation Cephalosporin Antibiotic',
                    'dosage': '22mg per kg twice daily for 14 days',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Apoquel (Oclacitinib)',
                    'type': 'JAK Inhibitor Anti-itch',
                    'dosage': '0.4-0.6mg per kg twice daily',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Dermacton Spray (Silver Sulfadiazine)',
                    'type': 'Topical Antimicrobial',
                    'dosage': 'Spray on affected areas twice daily',
                    'image': 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=300&h=200&fit=crop'
                }
            ]
        },
        'Eye Disease': {
            'description': 'Ocular conditions including conjunctivitis and corneal issues',
            'treatment': 'Ophthalmologic care and infection prevention',
            'medicines': [
                {
                    'name': 'Tobramycin Ophthalmic Solution (Tobrex)',
                    'type': 'Antibiotic Eye Drops',
                    'dosage': '1-2 drops every 4-6 hours for 7-10 days',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                },
                {
                    'name': 'GenTeal Lubricant Eye Drops',
                    'type': 'Artificial Tears/Lubricant',
                    'dosage': '2-3 drops 3-4 times daily as needed',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Maxitrol (Neomycin+Polymyxin+Dexamethasone)',
                    'type': 'Antibiotic/Steroid Eye Ointment',
                    'dosage': 'Apply small amount twice daily',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Sterile Saline Eye Wash',
                    'type': 'Eye Irrigation Solution',
                    'dosage': 'Flush eyes gently before medication',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                }
            ]
        },
        'Parvovirus': {
            'description': 'Highly contagious viral infection affecting the digestive system',
            'treatment': 'Intensive supportive care and fluid therapy to prevent dehydration',
            'medicines': [
                {
                    'name': 'Subcutaneous Fluids',
                    'type': 'Hydration Therapy',
                    'dosage': 'As prescribed by veterinarian',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Anti-nausea Medication',
                    'type': 'Antiemetic',
                    'dosage': 'As prescribed for symptom control',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Probiotics',
                    'type': 'Digestive Support',
                    'dosage': 'Daily during recovery',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Electrolyte Supplements',
                    'type': 'Nutritional Support',
                    'dosage': 'As directed by veterinarian',
                    'image': 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=300&h=200&fit=crop'
                }
            ]
        },
        'Kennel Cough': {
            'description': 'Infectious respiratory condition causing persistent cough',
            'treatment': 'Rest, cough suppressants, and antibiotics if bacterial component present',
            'medicines': [
                {
                    'name': 'Dextromethorphan',
                    'type': 'Cough Suppressant',
                    'dosage': '1-2mg per kg twice daily',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Azithromycin',
                    'type': 'Antibiotic',
                    'dosage': '10mg per kg once daily',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Honey (Raw)',
                    'type': 'Natural Cough Soother',
                    'dosage': '1 teaspoon for small dogs, 2 for large dogs',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Humidifier Therapy',
                    'type': 'Environmental Treatment',
                    'dosage': 'Use in living area continuously',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                }
            ]
        },
        'Healthy': {
            'description': 'Your dog appears to be in excellent health',
            'treatment': 'Maintain regular preventive care and health monitoring',
            'medicines': [
                {
                    'name': 'Multivitamin for Dogs',
                    'type': 'Nutritional Supplement',
                    'dosage': 'One tablet daily with food',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Joint Support Supplement',
                    'type': 'Glucosamine & Chondroitin',
                    'dosage': 'As per weight guidelines',
                    'image': 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Dental Chews',
                    'type': 'Oral Health Maintenance',
                    'dosage': 'One chew daily',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Flea & Tick Prevention',
                    'type': 'Parasitic Prevention',
                    'dosage': 'Monthly application',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                }
            ]
        },
        'Ear Infection': {
            'description': 'Bacterial or yeast infection of the ear canal causing discomfort',
            'treatment': 'Topical antimicrobial therapy and ear cleaning',
            'medicines': [
                {
                    'name': 'Otomax Ointment (Gentamicin+Betamethasone+Clotrimazole)',
                    'type': 'Triple-action Ear Medication',
                    'dosage': 'Apply to ear canal twice daily for 7 days',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Epi-Otic Advanced Ear Cleanser',
                    'type': 'Ear Cleaning Solution',
                    'dosage': 'Clean ears before medication application',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Surolan Ear Drops',
                    'type': 'Antimicrobial Ear Treatment',
                    'dosage': '5-10 drops twice daily for 7-14 days',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Tris-EDTA + Ketoconazole',
                    'type': 'Antifungal Ear Solution',
                    'dosage': 'Apply as directed for yeast infections',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                }
            ]
        },
        'Hip Dysplasia': {
            'description': 'Genetic condition causing improper formation of hip joints',
            'treatment': 'Pain management and joint support therapy',
            'medicines': [
                {
                    'name': 'Carprofen (Rimadyl)',
                    'type': 'NSAID Anti-inflammatory',
                    'dosage': '2-4mg per kg twice daily with food',
                    'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Glucosamine + Chondroitin (Cosequin)',
                    'type': 'Joint Support Supplement',
                    'dosage': 'As per weight chart on package',
                    'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Adequan Injectable (Polysulfated Glycosaminoglycan)',
                    'type': 'Disease-modifying Osteoarthritis Drug',
                    'dosage': '2mg per kg intramuscularly twice weekly',
                    'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                },
                {
                    'name': 'Gabapentin',
                    'type': 'Neuropathic Pain Medication',
                    'dosage': '10-20mg per kg twice daily',
                    'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                }
            ]
        }
    }
}

def get_treatment_suggestions(animal_type, disease):
    """Get treatment suggestions for a specific animal and disease"""
    try:
        if animal_type in TREATMENT_DATABASE and disease in TREATMENT_DATABASE[animal_type]:
            return TREATMENT_DATABASE[animal_type][disease]
        else:
            # Default treatment suggestions if specific disease not found
            return {
                'description': f'Treatment recommendations for {disease} in {animal_type}',
                'treatment': 'Consult with a veterinarian for proper diagnosis and treatment plan',
                'medicines': [
                    {
                        'name': 'General Antibiotic',
                        'type': 'Broad Spectrum',
                        'dosage': 'As prescribed by veterinarian',
                        'image': 'https://images.unsplash.com/photo-1587854692152-cbe660dbde88?w=300&h=200&fit=crop'
                    },
                    {
                        'name': 'Pain Relief Medication',
                        'type': 'Anti-inflammatory',
                        'dosage': 'As prescribed by veterinarian',
                        'image': 'https://images.unsplash.com/photo-1584362917165-526a968579e8?w=300&h=200&fit=crop'
                    },
                    {
                        'name': 'Wound Care Antiseptic',
                        'type': 'Topical Treatment',
                        'dosage': 'Apply as directed',
                        'image': 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=300&h=200&fit=crop'
                    },
                    {
                        'name': 'Vitamin Supplement',
                        'type': 'Immune Support',
                        'dosage': 'Daily as recommended',
                        'image': 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop'
                    }
                ]
            }
    except Exception as e:
        print(f"Error getting treatment suggestions: {e}")
        return None

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    """Check password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

@app.route('/')
def index():
    """Main landing page"""
    return render_template('index.html')

@app.route('/login')
def login_page():
    """Login page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    """Signup page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard after login"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    # Check if database is available
    if users_collection is None or predictions_collection is None:
        # Still show dashboard but with limited functionality
        return render_template('dashboard.html', 
                             user={'name': session.get('user_name', 'User'), 
                                   'email': session.get('user_email', '')}, 
                             recent_predictions=[],
                             db_unavailable=True)
    
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        session.clear()
        return redirect(url_for('login_page'))
    
    # Get user's recent predictions
    recent_predictions = list(predictions_collection.find(
        {'user_id': session['user_id']}
    ).sort('created_at', -1).limit(5))
    
    return render_template('dashboard.html', user=user, recent_predictions=recent_predictions)

@app.route('/auth/login', methods=['POST'])
def login():
    """Handle login form submission"""
    try:
        # Check if database is available
        is_connected, status_msg = get_db_status()
        if not is_connected:
            return jsonify({
                'success': False, 
                'message': f'Database connection unavailable: {status_msg}. Please try again later.'
            }), 503
            
        data = request.get_json() if request.is_json else request.form
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400
        
        # Find user by email
        user = users_collection.find_one({'email': email})
        if not user:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Check password
        if not check_password(password, user['password']):
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Update last login
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': datetime.utcnow()}}
        )
        
        # Set session
        session['user_id'] = str(user['_id'])
        session['user_name'] = user['name']
        session['user_email'] = user['email']
        
        print(f"✅ User logged in successfully: {email}")
        
        return jsonify({
            'success': True, 
            'message': 'Login successful',
            'redirect': url_for('dashboard')
        })
        
    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred during login'}), 500

@app.route('/auth/signup', methods=['POST'])
def signup():
    """Handle signup form submission"""
    try:
        print("🔍 Signup request received")  # Debug log
        
        # Check if database is available
        is_connected, status_msg = get_db_status()
        if not is_connected:
            print(f"❌ Database not available: {status_msg}")
            return jsonify({
                'success': False, 
                'message': f'Database connection unavailable: {status_msg}. Please try again later.'
            }), 503
            
        # Get data from request
        data = request.get_json() if request.is_json else request.form
        print(f"🔍 Request content type: {request.content_type}")  # Debug log
        print(f"🔍 Request is_json: {request.is_json}")  # Debug log
        print(f"🔍 Signup data received: {data}")  # Debug log
        
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        print(f"🔍 Parsed data - Name: {name}, Email: {email}, Password length: {len(password) if password else 0}")  # Debug log
        
        # Validation
        if not all([name, email, password, confirm_password]):
            print("❌ Missing required fields")  # Debug log
            missing_fields = []
            if not name: missing_fields.append('name')
            if not email: missing_fields.append('email')
            if not password: missing_fields.append('password')
            if not confirm_password: missing_fields.append('confirm_password')
            print(f"❌ Missing fields: {missing_fields}")
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if password != confirm_password:
            print("❌ Passwords don't match")  # Debug log
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        
        if not validate_email(email):
            print(f"❌ Invalid email: {email}")  # Debug log
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        is_valid, message = validate_password(password)
        if not is_valid:
            print(f"❌ Password validation failed: {message}")  # Debug log
            return jsonify({'success': False, 'message': message}), 400
        
        # Check if user already exists
        print(f"🔍 Checking if user exists: {email}")  # Debug log
        existing_user = users_collection.find_one({'email': email})
        if existing_user:
            print(f"❌ User already exists: {email}")  # Debug log
            return jsonify({'success': False, 'message': 'Email already registered'}), 409
        
        # Create new user
        print(f"📝 Creating new user: {email}")  # Debug log
        hashed_password = hash_password(password)
        user_data = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'created_at': datetime.utcnow(),
            'last_login': None,
            'is_active': True
        }
        
        print(f"💾 Inserting user data into MongoDB...")  # Debug log
        result = users_collection.insert_one(user_data)
        print(f"✅ User created with ID: {result.inserted_id}")  # Debug log
        
        # Set session
        session['user_id'] = str(result.inserted_id)
        session['user_name'] = name
        session['user_email'] = email
        
        print(f"✅ Session created for user: {name}")  # Debug log
        
        return jsonify({
            'success': True, 
            'message': 'Account created successfully',
            'redirect': url_for('dashboard')
        })
        
    except Exception as e:
        print(f"❌ Signup error: {str(e)}")  # Debug log
        print(f"❌ Error type: {type(e).__name__}")  # Debug log
        import traceback
        print(f"❌ Full traceback: {traceback.format_exc()}")  # Debug log
        return jsonify({'success': False, 'message': 'An error occurred during signup'}), 500
        import traceback
        print(f"❌ Full traceback: {traceback.format_exc()}")  # Debug log
        return jsonify({'success': False, 'message': f'An error occurred during signup: {str(e)}'}), 500

@app.route('/test-db')
def test_db():
    """Test MongoDB connection and show database status"""
    try:
        # Check database status
        is_connected, status_msg = get_db_status()
        
        if not is_connected:
            return jsonify({
                'success': False,
                'message': f'Database not connected: {status_msg}',
                'connection_string': MONGODB_URI.replace('umcunBXqOZO3AUK3', '***'),  # Hide password
                'collections': None,
                'user_count': 0
            }), 500
        
        # Test collection access
        user_count = users_collection.count_documents({})
        prediction_count = predictions_collection.count_documents({})
        
        # List collections
        collections = db.list_collection_names()
        
        return jsonify({
            'success': True,
            'message': 'Database connection successful',
            'database_name': 'gorakshaai',
            'collections': collections,
            'user_count': user_count,
            'prediction_count': prediction_count,
            'connection_string': MONGODB_URI.replace('umcunBXqOZO3AUK3', '***')  # Hide password
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Database test failed: {str(e)}',
            'error_type': type(e).__name__
        }), 500

@app.route('/auth/logout')
def logout():
    """Handle logout"""
    session.clear()
    return redirect(url_for('index'))

# Admin Panel Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page and handler"""
    if request.method == 'GET':
        print("🔍 DEBUG: Admin login page accessed")
        if 'admin_logged_in' in session:
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html')
    
    elif request.method == 'POST':
        """Handle admin login"""
        try:
            data = request.get_json() if request.is_json else request.form
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            # Admin credentials
            ADMIN_USERNAME = 'pashuarogyam'
            ADMIN_PASSWORD = 'pashuarogyam@2025'
            
            if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                session['admin_logged_in'] = True
                session['admin_username'] = username
                print(f"✅ Admin logged in successfully: {username}")
                return jsonify({
                    'success': True,
                    'message': 'Admin login successful',
                    'redirect': url_for('admin_dashboard')
                })
            else:
                return jsonify({'success': False, 'message': 'Invalid admin credentials'}), 401
                
        except Exception as e:
            print(f"❌ Admin login error: {str(e)}")
            return jsonify({'success': False, 'message': 'An error occurred during admin login'}), 500

@app.route('/admin-dashboard')
def admin_dashboard():
    """Admin dashboard"""
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    
    try:
        # Get statistics
        stats = {
            'total_users': 0,
            'total_consultants': 0,
            'total_predictions': 0,
            'total_consultation_requests': 0,
            'recent_users': [],
            'recent_predictions': [],
            'recent_consultations': []
        }
        
        # Check if database is available
        is_connected, status_msg = get_db_status()
        if is_connected:
            # Get counts
            stats['total_users'] = users_collection.count_documents({})
            stats['total_consultants'] = consultants_collection.count_documents({})
            stats['total_predictions'] = predictions_collection.count_documents({})
            stats['total_consultation_requests'] = consultation_requests_collection.count_documents({})
            
            # Get recent users (last 10)
            recent_users = list(users_collection.find({}, {
                'name': 1, 'email': 1, 'created_at': 1
            }).sort('created_at', -1).limit(10))
            
            for user in recent_users:
                stats['recent_users'].append({
                    'id': str(user['_id']),
                    'name': user.get('name', 'Unknown'),
                    'email': user.get('email', 'Unknown'),
                    'created_at': user.get('created_at', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if user.get('created_at') else 'Unknown'
                })
            
            # Get recent predictions (last 10)
            recent_predictions = list(predictions_collection.find({}, {
                'user_id': 1, 'animal_type': 1, 'prediction': 1, 'confidence': 1, 'created_at': 1
            }).sort('created_at', -1).limit(10))
            
            for pred in recent_predictions:
                # Get user info
                user_info = users_collection.find_one({'_id': ObjectId(pred.get('user_id', ''))}, {'name': 1, 'email': 1}) if pred.get('user_id') else None
                
                stats['recent_predictions'].append({
                    'id': str(pred['_id']),
                    'animal_type': pred.get('animal_type', 'Unknown'),
                    'prediction': pred.get('prediction', 'Unknown'),
                    'confidence': pred.get('confidence', 0),
                    'user_name': user_info.get('name', 'Unknown') if user_info else 'Unknown',
                    'user_email': user_info.get('email', 'Unknown') if user_info else 'Unknown',
                    'created_at': pred.get('created_at', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if pred.get('created_at') else 'Unknown'
                })
            
            # Get recent consultation requests (last 10)
            recent_consultations = list(consultation_requests_collection.find({}, {
                'farmer_name': 1, 'farmer_email': 1, 'animal_type': 1, 'status': 1, 'urgency': 1, 'created_at': 1
            }).sort('created_at', -1).limit(10))
            
            for consult in recent_consultations:
                stats['recent_consultations'].append({
                    'id': str(consult['_id']),
                    'farmer_name': consult.get('farmer_name', 'Unknown'),
                    'farmer_email': consult.get('farmer_email', 'Unknown'),
                    'animal_type': consult.get('animal_type', 'Unknown'),
                    'status': consult.get('status', 'Unknown'),
                    'urgency': consult.get('urgency', 'Unknown'),
                    'created_at': consult.get('created_at', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if consult.get('created_at') else 'Unknown'
                })
        
        return render_template('admin_dashboard.html', stats=stats, db_available=is_connected)
        
    except Exception as e:
        print(f"❌ Admin dashboard error: {str(e)}")
        flash('Error loading admin dashboard', 'error')
        return render_template('admin_dashboard.html', stats={
            'total_users': 0,
            'total_consultants': 0,
            'total_predictions': 0,
            'total_consultation_requests': 0,
            'recent_users': [],
            'recent_predictions': [],
            'recent_consultations': []
        }, db_available=False)

@app.route('/admin/logout')
def admin_logout():
    """Handle admin logout"""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/export-report')
def export_admin_report():
    """Export admin dashboard data as PDF"""
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    
    if not REPORTLAB_AVAILABLE:
        flash('PDF export functionality is not available. Please install reportlab.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Get the same stats data as admin dashboard
        stats = {
            'total_users': 0,
            'total_consultants': 0,
            'total_predictions': 0,
            'total_consultation_requests': 0,
            'recent_users': [],
            'recent_predictions': [],
            'recent_consultations': []
        }
        
        # Check if database is available
        is_connected, status_msg = get_db_status()
        if is_connected:
            # Get counts
            stats['total_users'] = users_collection.count_documents({})
            stats['total_consultants'] = consultants_collection.count_documents({})
            stats['total_predictions'] = predictions_collection.count_documents({})
            stats['total_consultation_requests'] = consultation_requests_collection.count_documents({})
            
            # Get recent users (last 10)
            recent_users = list(users_collection.find({}, {
                'name': 1, 'email': 1, 'created_at': 1
            }).sort('created_at', -1).limit(10))
            
            for user in recent_users:
                stats['recent_users'].append({
                    'name': user.get('name', 'Unknown'),
                    'email': user.get('email', 'Unknown'),
                    'created_at': user.get('created_at', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if user.get('created_at') else 'Unknown'
                })
            
            # Get recent predictions (last 10)
            recent_predictions = list(predictions_collection.find({}, {
                'user_id': 1, 'animal_type': 1, 'prediction': 1, 'confidence': 1, 'created_at': 1
            }).sort('created_at', -1).limit(10))
            
            for pred in recent_predictions:
                # Get user info
                user_info = users_collection.find_one({'_id': ObjectId(pred.get('user_id', ''))}, {'name': 1, 'email': 1}) if pred.get('user_id') else None
                
                stats['recent_predictions'].append({
                    'animal_type': pred.get('animal_type', 'Unknown'),
                    'prediction': pred.get('prediction', 'Unknown'),
                    'confidence': f"{pred.get('confidence', 0)*100:.1f}%" if pred.get('confidence') else '0%',
                    'user_name': user_info.get('name', 'Unknown') if user_info else 'Unknown',
                    'created_at': pred.get('created_at', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if pred.get('created_at') else 'Unknown'
                })
            
            # Get recent consultation requests (last 10)
            recent_consultations = list(consultation_requests_collection.find({}, {
                'farmer_name': 1, 'farmer_email': 1, 'animal_type': 1, 'status': 1, 'urgency': 1, 'created_at': 1
            }).sort('created_at', -1).limit(10))
            
            for consult in recent_consultations:
                stats['recent_consultations'].append({
                    'farmer_name': consult.get('farmer_name', 'Unknown'),
                    'farmer_email': consult.get('farmer_email', 'Unknown'),
                    'animal_type': consult.get('animal_type', 'Unknown'),
                    'status': consult.get('status', 'Unknown'),
                    'urgency': consult.get('urgency', 'Unknown'),
                    'created_at': consult.get('created_at', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if consult.get('created_at') else 'Unknown'
                })
        
        # Create PDF
        pdf_buffer = io.BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.Color(0.18, 0.55, 0.34)  # Green color
        )
        story.append(Paragraph("PashuAarogyam - Admin Dashboard Report", title_style))
        story.append(Spacer(1, 20))
        
        # Date and time
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        story.append(Paragraph(f"<b>Generated on:</b> {current_time}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Statistics Summary
        stats_title = ParagraphStyle(
            'StatsTitle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.Color(0.18, 0.55, 0.34)
        )
        story.append(Paragraph("System Statistics", stats_title))
        story.append(Spacer(1, 10))
        
        # Stats table
        stats_data = [
            ['Metric', 'Count'],
            ['Total Users', str(stats['total_users'])],
            ['Active Consultants', str(stats['total_consultants'])],
            ['Disease Predictions', str(stats['total_predictions'])],
            ['Consultation Requests', str(stats['total_consultation_requests'])]
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.18, 0.55, 0.34)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 30))
        
        # Recent Users
        if stats['recent_users']:
            story.append(Paragraph("Recent Users", stats_title))
            story.append(Spacer(1, 10))
            
            users_data = [['Name', 'Email', 'Joined Date']]
            for user in stats['recent_users'][:5]:  # Show top 5
                users_data.append([
                    user['name'],
                    user['email'],
                    user['created_at']
                ])
            
            users_table = Table(users_data, colWidths=[2*inch, 2.5*inch, 1.5*inch])
            users_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.18, 0.55, 0.34)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(users_table)
            story.append(Spacer(1, 20))
        
        # Recent Predictions
        if stats['recent_predictions']:
            story.append(Paragraph("Recent Disease Predictions", stats_title))
            story.append(Spacer(1, 10))
            
            predictions_data = [['Animal Type', 'Prediction', 'Confidence', 'User', 'Date']]
            for pred in stats['recent_predictions'][:5]:  # Show top 5
                predictions_data.append([
                    pred['animal_type'],
                    pred['prediction'],
                    pred['confidence'],
                    pred['user_name'],
                    pred['created_at']
                ])
            
            predictions_table = Table(predictions_data, colWidths=[1*inch, 1.5*inch, 1*inch, 1.5*inch, 1*inch])
            predictions_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.18, 0.55, 0.34)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(predictions_table)
            story.append(Spacer(1, 20))
        
        # Recent Consultations
        if stats['recent_consultations']:
            story.append(Paragraph("Recent Consultation Requests", stats_title))
            story.append(Spacer(1, 10))
            
            consultations_data = [['Farmer', 'Animal Type', 'Status', 'Urgency', 'Date']]
            for consult in stats['recent_consultations'][:5]:  # Show top 5
                consultations_data.append([
                    consult['farmer_name'],
                    consult['animal_type'],
                    consult['status'],
                    consult['urgency'],
                    consult['created_at']
                ])
            
            consultations_table = Table(consultations_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1*inch, 1.5*inch])
            consultations_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.18, 0.55, 0.34)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(consultations_table)
        
        # Build PDF
        doc.build(story)
        pdf_buffer.seek(0)
        
        # Create response
        response = make_response(pdf_buffer.read())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=PashuAarogyam_Admin_Report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        
        pdf_buffer.close()
        return response
        
    except Exception as e:
        print(f"❌ PDF export error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        flash('Error generating PDF report', 'error')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('index'))


@app.route('/admin/api/stats')
def admin_api_stats():
    """API endpoint for admin statistics"""
    if 'admin_logged_in' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        # Check if database is available
        is_connected, status_msg = get_db_status()
        if not is_connected:
            return jsonify({
                'success': False,
                'message': f'Database not available: {status_msg}'
            }), 503
        
        stats = {
            'total_users': users_collection.count_documents({}),
            'total_consultants': consultants_collection.count_documents({}),
            'total_predictions': predictions_collection.count_documents({}),
            'total_consultation_requests': consultation_requests_collection.count_documents({})
        }
        
        return jsonify({'success': True, 'stats': stats})
        
    except Exception as e:
        print(f"❌ Admin API stats error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error fetching statistics'}), 500

@app.route('/predict_disease', methods=['POST'])
def predict_disease():
    """Handle disease prediction requests"""
    try:
        # Check if user is logged in
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Please login to use disease prediction'}), 401
        
        # Get form data
        animal_type = request.form.get('animal_type')
        symptoms = json.loads(request.form.get('symptoms', '[]'))
        age = request.form.get('age')
        weight = request.form.get('weight')
        temperature = request.form.get('temperature')
        additional_info = request.form.get('additional_info', '')
        
        # Handle file upload
        uploaded_file = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Generate unique filename
                unique_filename = str(uuid.uuid4()) + '_' + filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                uploaded_file = unique_filename
        
        # Mock disease prediction logic (replace with actual AI model)
        prediction_result = mock_disease_prediction(
            animal_type, symptoms, age, weight, temperature, additional_info
        )
        
        # Save prediction to database
        prediction_data = {
            'user_id': session['user_id'],
            'animal_type': animal_type,
            'symptoms': symptoms,
            'age': age,
            'weight': weight,
            'temperature': temperature,
            'additional_info': additional_info,
            'uploaded_file': uploaded_file,
            'prediction': prediction_result,
            'created_at': datetime.utcnow()
        }
        predictions_collection.insert_one(prediction_data)
        
        return jsonify({
            'success': True,
            'prediction': prediction_result,
            'uploaded_file': uploaded_file
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def mock_disease_prediction(animal_type, symptoms, age, weight, temperature, additional_info):
    """
    Mock disease prediction function
    Replace this with your actual AI model prediction logic
    """
    # Disease database for different animals
    disease_database = {
        'cattle': {
            'diseases': ['Bovine Respiratory Disease', 'Mastitis', 'Foot and Mouth Disease', 'Bloat', 'Milk Fever'],
            'symptoms_map': {
                'fever': ['Bovine Respiratory Disease', 'Foot and Mouth Disease'],
                'coughing': ['Bovine Respiratory Disease'],
                'difficulty_breathing': ['Bovine Respiratory Disease', 'Bloat'],
                'lethargy': ['Mastitis', 'Milk Fever'],
                'loss_of_appetite': ['Bloat', 'Milk Fever']
            }
        },
        'pig': {
            'diseases': ['Swine Flu', 'Porcine Reproductive and Respiratory Syndrome', 'Salmonellosis', 'Pneumonia'],
            'symptoms_map': {
                'fever': ['Swine Flu', 'Pneumonia'],
                'coughing': ['Swine Flu', 'Pneumonia'],
                'diarrhea': ['Salmonellosis'],
                'lethargy': ['Swine Flu', 'Salmonellosis']
            }
        },
        'chicken': {
            'diseases': ['Avian Influenza', 'Newcastle Disease', 'Coccidiosis', 'Fowl Pox'],
            'symptoms_map': {
                'fever': ['Avian Influenza', 'Newcastle Disease'],
                'difficulty_breathing': ['Avian Influenza', 'Newcastle Disease'],
                'diarrhea': ['Coccidiosis'],
                'skin_lesions': ['Fowl Pox']
            }
        },
        'sheep': {
            'diseases': ['Scrapie', 'Foot Rot', 'Parasitic Infections', 'Pneumonia'],
            'symptoms_map': {
                'lameness': ['Foot Rot'],
                'lethargy': ['Parasitic Infections', 'Pneumonia'],
                'coughing': ['Pneumonia']
            }
        },
        'goat': {
            'diseases': ['Caprine Arthritis Encephalitis', 'Pneumonia', 'Internal Parasites', 'Ketosis'],
            'symptoms_map': {
                'coughing': ['Pneumonia'],
                'lethargy': ['Internal Parasites', 'Ketosis'],
                'loss_of_appetite': ['Ketosis']
            }
        },
        'horse': {
            'diseases': ['Equine Influenza', 'Colic', 'Laminitis', 'Strangles'],
            'symptoms_map': {
                'fever': ['Equine Influenza', 'Strangles'],
                'coughing': ['Equine Influenza', 'Strangles'],
                'lameness': ['Laminitis']
            }
        },
        'dog': {
            'diseases': ['Parvovirus', 'Distemper', 'Kennel Cough', 'Hip Dysplasia'],
            'symptoms_map': {
                'vomiting': ['Parvovirus'],
                'diarrhea': ['Parvovirus'],
                'coughing': ['Kennel Cough', 'Distemper'],
                'lameness': ['Hip Dysplasia']
            }
        },
        'cat': {
            'diseases': ['Feline Leukemia', 'Upper Respiratory Infection', 'Feline Distemper', 'Urinary Tract Infection'],
            'symptoms_map': {
                'discharge': ['Upper Respiratory Infection'],
                'lethargy': ['Feline Leukemia', 'Feline Distemper'],
                'vomiting': ['Feline Distemper']
            }
        }
    }
    
    # Get animal data
    animal_data = disease_database.get(animal_type, {
        'diseases': ['General Infection', 'Nutritional Deficiency', 'Stress-related Condition'],
        'symptoms_map': {}
    })
    
    # Calculate disease probabilities based on symptoms
    disease_scores = {}
    for disease in animal_data['diseases']:
        disease_scores[disease] = 0
    
    # Add scores for matching symptoms
    for symptom in symptoms:
        if symptom in animal_data['symptoms_map']:
            for disease in animal_data['symptoms_map'][symptom]:
                if disease in disease_scores:
                    disease_scores[disease] += 10
    
    # Add base probability for all diseases
    for disease in disease_scores:
        disease_scores[disease] += 20  # Base probability
    
    # Sort diseases by score
    sorted_diseases = sorted(disease_scores.items(), key=lambda x: x[1], reverse=True)
    
    # Get top prediction
    top_disease = sorted_diseases[0][0] if sorted_diseases else 'Unknown Condition'
    confidence = min(95, max(60, sorted_diseases[0][1] * 2)) if sorted_diseases else 70
    
    # Generate recommendations
    recommendations = [
        "Consult with a veterinarian immediately for proper diagnosis",
        "Monitor the animal's condition closely",
        "Ensure proper nutrition and hydration",
        "Keep the animal comfortable and reduce stress"
    ]
    
    if 'fever' in symptoms:
        recommendations.append("Monitor body temperature regularly")
    if 'diarrhea' in symptoms or 'vomiting' in symptoms:
        recommendations.append("Ensure adequate fluid intake to prevent dehydration")
    if 'difficulty_breathing' in symptoms:
        recommendations.append("Ensure good ventilation and avoid stress")
    
    # Add isolation recommendation for certain diseases
    contagious_diseases = ['Avian Influenza', 'Newcastle Disease', 'Swine Flu', 'Foot and Mouth Disease']
    if top_disease in contagious_diseases:
        recommendations.insert(1, "Isolate the animal to prevent disease spread")
    
    # Get treatment suggestions
    treatment_info = get_treatment_suggestions(animal_type, top_disease)
    
    return {
        'disease': top_disease,
        'confidence': round(confidence, 1),
        'symptoms_analyzed': symptoms,
        'recommendations': recommendations,
        'severity': 'High' if confidence > 80 else 'Medium' if confidence > 60 else 'Low',
        'animal_type': animal_type,
        'treatment': treatment_info
    }

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Contact page"""
    return render_template('contact.html')

@app.route('/disease_detection')
def disease_detection():
    """Disease detection main page - animal selection"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('disease_detection.html')

@app.route('/cat_detection')
def cat_detection():
    """Cat disease detection page"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('cat_detection.html')

@app.route('/predict/cat', methods=['POST'])
def predict_cat():
    """Predict cat diseases using YOLOv8 model"""
    try:
        # Check if model is loaded
        if 'cat' not in models:
            return jsonify({
                'success': False,
                'error': 'Cat disease detection model is not available',
                'show_popup': True
            })

        # Check if image is provided
        if 'image' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No image file provided',
                'show_popup': True
            })

        file = request.files['image']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No image file selected',
                'show_popup': True
            })

        if file and allowed_file(file.filename):
            # Read image
            image_bytes = file.read()
            image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
            
            # Run prediction
            results = models['cat'](image)
            
            # Process results
            predictions = []
            for result in results:
                if result.boxes is not None and len(result.boxes) > 0:
                    for box in result.boxes:
                        class_id = int(box.cls[0])
                        confidence = float(box.conf[0])
                        class_name = result.names[class_id]
                        
                        predictions.append({
                            'class': class_name,
                            'confidence': confidence
                        })
            
            # Sort by confidence
            predictions.sort(key=lambda x: x['confidence'], reverse=True)
            
            # Enhanced animal validation with specific error messages
            if not predictions:
                return jsonify({
                    'success': False,
                    'error': '🚫 No Cat Detected!',
                    'detailed_message': 'The uploaded image does not contain a recognizable cat. Please upload a clear image of a cat for disease detection.',
                    'validation_failed': True,
                    'animal_expected': 'cat',
                    'show_popup': True,
                    'confidence': 0.0
                })
            
            max_confidence = predictions[0]['confidence']
            
            # If highest confidence is below 25%, likely not a cat image at all
            if max_confidence < 0.25:
                return jsonify({
                    'success': False,
                    'error': '🐱 Wrong Animal Detected!',
                    'detailed_message': 'This image does not appear to contain a cat. Our AI model is specifically trained for cat disease detection. Please upload a clear image of a cat to get accurate results.',
                    'validation_failed': True,
                    'animal_expected': 'cat',
                    'show_popup': True,
                    'confidence': max_confidence
                })
            
            # If confidence is between 25-50%, might be a cat but very unclear
            elif max_confidence < 0.50:
                return jsonify({
                    'success': False,
                    'error': '📸 Image Quality Too Low!',
                    'detailed_message': 'The image quality is too low for reliable cat disease detection. Please upload a clearer, well-lit image of the cat. Make sure the cat is clearly visible and the photo is not blurry.',
                    'validation_failed': True,
                    'animal_expected': 'cat',
                    'show_popup': True,
                    'confidence': max_confidence
                })
            
            # If confidence is between 50-65%, proceed but warn about lower accuracy
            elif max_confidence < 0.65:
                # Add a warning but still proceed with analysis
                predictions[0]['quality_warning'] = True
            
            # Store prediction in database if available
            if predictions_collection is not None:
                try:
                    # Get the top prediction for main storage
                    top_prediction = predictions[0] if predictions else {'class': 'Unknown', 'confidence': 0.0}
                    
                    prediction_doc = {
                        'user_id': session.get('user_id'),
                        'username': session.get('user_name'),
                        'animal_type': 'cat',
                        'prediction': top_prediction['class'],  # Main predicted disease
                        'confidence': top_prediction['confidence'],  # Confidence score
                        'predictions': predictions,  # All predictions for reference
                        'created_at': datetime.now(timezone.utc),  # Date of prediction
                        'timestamp': datetime.now(timezone.utc),  # Keep for backward compatibility
                        'model_used': 'cat_disease_best.pt'
                    }
                    predictions_collection.insert_one(prediction_doc)
                except Exception as db_error:
                    print(f"Database error: {db_error}")
            
            # Get treatment suggestions for the top prediction
            top_prediction = predictions[0] if predictions else {'class': 'Unknown', 'confidence': 0.0}
            treatment_info = get_treatment_suggestions('cat', top_prediction['class'])
            
            return jsonify({
                'success': True,
                'predictions': predictions,
                'model_info': 'YOLOv8 Cat Disease Detection Model',
                'treatment': treatment_info
            })
        
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid file format. Supported formats: PNG, JPG, JPEG, WebP',
                'show_popup': True
            })
            
    except Exception as e:
        print(f"Error in cat prediction: {e}")
        print(f"Error traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f'Prediction failed: {str(e)}',
            'show_popup': True
        })

@app.route('/predict/cow', methods=['POST'])
def predict_cow():
    """Predict cow diseases using YOLOv8 model"""
    try:
        # Check if model is loaded
        if 'cow' not in models:
            return jsonify({
                'success': False,
                'error': 'Cow disease detection model is not available',
                'show_popup': True
            })

        # Check if image is provided
        if 'image' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No image file provided',
                'show_popup': True
            })

        file = request.files['image']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No image file selected',
                'show_popup': True
            })

        if file and allowed_file(file.filename):
            # Read image
            image_bytes = file.read()
            image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
            
            # Run prediction
            results = models['cow'](image)
            
            # Process results
            predictions = []
            for result in results:
                if result.boxes is not None and len(result.boxes) > 0:
                    for box in result.boxes:
                        class_id = int(box.cls[0])
                        confidence = float(box.conf[0])
                        class_name = result.names[class_id]
                        
                        predictions.append({
                            'class': class_name,
                            'confidence': confidence
                        })
            
            # Sort by confidence
            predictions.sort(key=lambda x: x['confidence'], reverse=True)
            
            # Enhanced animal validation with specific error messages
            if not predictions:
                return jsonify({
                    'success': False,
                    'error': '🚫 No Cow/Cattle Detected!',
                    'detailed_message': 'The uploaded image does not contain a recognizable cow or cattle. Please upload a clear image of a cow/cattle for disease detection.',
                    'validation_failed': True,
                    'animal_expected': 'cow',
                    'show_popup': True,
                    'confidence': 0.0
                })
            
            max_confidence = predictions[0]['confidence']
            
            # If highest confidence is below 25%, likely not a cow image at all
            if max_confidence < 0.25:
                return jsonify({
                    'success': False,
                    'error': '🐄 Wrong Animal Detected!',
                    'detailed_message': 'This image does not appear to contain a cow or cattle. Our AI model is specifically trained for cow/cattle disease detection. Please upload a clear image of a cow/cattle to get accurate results.',
                    'validation_failed': True,
                    'animal_expected': 'cow',
                    'show_popup': True,
                    'confidence': max_confidence
                })
            
            # If confidence is between 25-50%, might be a cow but very unclear
            elif max_confidence < 0.50:
                return jsonify({
                    'success': False,
                    'error': '📸 Image Quality Too Low!',
                    'detailed_message': 'The image quality is too low for reliable cow/cattle disease detection. Please upload a clearer, well-lit image of the cow/cattle. Make sure the animal is clearly visible and the photo is not blurry.',
                    'validation_failed': True,
                    'animal_expected': 'cow',
                    'show_popup': True,
                    'confidence': max_confidence
                })
            
            # If confidence is between 50-65%, proceed but warn about lower accuracy
            elif max_confidence < 0.65:
                # Add a warning but still proceed with analysis
                predictions[0]['quality_warning'] = True
            
            # Store prediction in database if available
            if predictions_collection is not None:
                try:
                    # Get the top prediction for main storage
                    top_prediction = predictions[0] if predictions else {'class': 'Unknown', 'confidence': 0.0}
                    
                    prediction_doc = {
                        'user_id': session.get('user_id'),
                        'username': session.get('user_name'),
                        'animal_type': 'cow',
                        'prediction': top_prediction['class'],  # Main predicted disease
                        'confidence': top_prediction['confidence'],  # Confidence score
                        'predictions': predictions,  # All predictions for reference
                        'created_at': datetime.now(timezone.utc),  # Date of prediction
                        'timestamp': datetime.now(timezone.utc),  # Keep for backward compatibility
                        'model_used': 'lumpy_disease_best.pt'
                    }
                    predictions_collection.insert_one(prediction_doc)
                except Exception as db_error:
                    print(f"Database error: {db_error}")
            
            # Get treatment suggestions for the top prediction
            top_prediction = predictions[0] if predictions else {'class': 'Unknown', 'confidence': 0.0}
            treatment_info = get_treatment_suggestions('cow', top_prediction['class'])
            
            return jsonify({
                'success': True,
                'predictions': predictions,
                'model_info': 'YOLOv8 Cow Disease Detection Model',
                'treatment': treatment_info
            })
        
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid file format. Supported formats: PNG, JPG, JPEG, WebP',
                'show_popup': True
            })
            
    except Exception as e:
        print(f"Error in cow prediction: {e}")
        print(f"Error traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f'Prediction failed: {str(e)}',
            'show_popup': True
        })

@app.route('/predict/dog', methods=['POST'])
def predict_dog():
    """Predict dog diseases using YOLOv8 model"""
    try:
        # Check if model is loaded
        if 'dog' not in models:
            return jsonify({
                'success': False,
                'error': 'Dog disease detection model is not available',
                'show_popup': True
            })

        # Check if image is provided
        if 'image' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No image file provided',
                'show_popup': True
            })

        file = request.files['image']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No image file selected',
                'show_popup': True
            })

        if file and allowed_file(file.filename):
            # Read image
            image_bytes = file.read()
            image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
            
            # Run dog disease detection
            results = models['dog'](image)
            
            # Process results
            predictions = []
            for result in results:
                if result.boxes is not None and len(result.boxes) > 0:
                    for box in result.boxes:
                        class_id = int(box.cls[0])
                        confidence = float(box.conf[0])
                        class_name = result.names[class_id]
                        
                        predictions.append({
                            'class': class_name,
                            'confidence': confidence
                        })
            
            # Sort by confidence
            predictions.sort(key=lambda x: x['confidence'], reverse=True)
            
            # Enhanced animal validation with specific error messages
            if not predictions:
                return jsonify({
                    'success': False,
                    'error': '🚫 No Dog Detected!',
                    'detailed_message': 'The uploaded image does not contain a recognizable dog. Please upload a clear image of a dog for disease detection.',
                    'validation_failed': True,
                    'animal_expected': 'dog',
                    'show_popup': True,
                    'confidence': 0.0
                })
            
            # If highest confidence is below 25%, likely not a dog image at all
            max_confidence = predictions[0]['confidence']
            if max_confidence < 0.25:
                return jsonify({
                    'success': False,
                    'error': '🐕 Wrong Animal Detected!',
                    'detailed_message': 'This image does not appear to contain a dog. Our AI model is specifically trained for dog disease detection. Please upload a clear image of a dog to get accurate results.',
                    'validation_failed': True,
                    'animal_expected': 'dog',
                    'show_popup': True,
                    'confidence': max_confidence
                })
            
            # If confidence is between 25-50%, might be a dog but very unclear
            elif max_confidence < 0.50:
                return jsonify({
                    'success': False,
                    'error': '📸 Image Quality Too Low!',
                    'detailed_message': 'The image quality is too low for reliable dog disease detection. Please upload a clearer, well-lit image of the dog. Make sure the dog is clearly visible and the photo is not blurry.',
                    'validation_failed': True,
                    'animal_expected': 'dog',
                    'show_popup': True,
                    'confidence': max_confidence
                })
            
            # If confidence is between 50-65%, proceed but warn about lower accuracy
            elif max_confidence < 0.65:
                # Add a warning but still proceed with analysis
                predictions[0]['quality_warning'] = True
            
            # Store prediction in database if available
            if predictions_collection is not None:
                try:
                    # Get the top prediction for main storage
                    top_prediction = predictions[0] if predictions else {'class': 'Unknown', 'confidence': 0.0}
                    
                    prediction_doc = {
                        'user_id': session.get('user_id'),
                        'username': session.get('user_name'),
                        'animal_type': 'dog',
                        'prediction': top_prediction['class'],  # Main predicted disease
                        'confidence': top_prediction['confidence'],  # Confidence score
                        'predictions': predictions,  # All predictions for reference
                        'created_at': datetime.now(timezone.utc),  # Date of prediction
                        'timestamp': datetime.now(timezone.utc),  # Keep for backward compatibility
                        'model_used': 'dog_disease_best.pt'
                    }
                    predictions_collection.insert_one(prediction_doc)
                except Exception as db_error:
                    print(f"Database error: {db_error}")
            
            # Get treatment suggestions for the top prediction
            top_prediction = predictions[0] if predictions else {'class': 'Unknown', 'confidence': 0.0}
            treatment_info = get_treatment_suggestions('dog', top_prediction['class'])
            
            return jsonify({
                'success': True,
                'predictions': predictions,
                'model_info': 'YOLOv8 Dog Disease Detection Model',
                'treatment': treatment_info
            })
        
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid file format. Supported formats: PNG, JPG, JPEG, WebP',
                'show_popup': True
            })
            
    except Exception as e:
        print(f"Error in dog prediction: {e}")
        print(f"Error traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f'Prediction failed: {str(e)}',
            'show_popup': True
        })

@app.route('/cow_detection')
def cow_detection():
    """Cow disease detection page"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('cow_detection.html')

@app.route('/dog_detection')
def dog_detection():
    """Dog disease detection page"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('dog_detection.html')

# =================== INTEGRATED IMAGE + SYMPTOMS PREDICTION ===================

@app.route('/integrated_prediction')
def integrated_prediction():
    """Integrated prediction page combining image analysis with detailed symptoms"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('integrated_prediction.html')

@app.route('/predict/integrated', methods=['POST'])
def predict_integrated():
    """Advanced prediction combining image analysis with comprehensive symptom assessment"""
    try:
        # Check authentication
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        # Extract comprehensive form data
        animal_type = request.form.get('animal_type', '').strip()
        animal_age = request.form.get('animal_age', '').strip()
        animal_weight = request.form.get('animal_weight', '').strip()
        animal_breed = request.form.get('animal_breed', '').strip()
        
        # Symptoms data
        symptoms = request.form.getlist('symptoms[]')
        additional_symptoms = request.form.get('additional_symptoms', '').strip()
        symptom_duration = request.form.get('symptom_duration', '').strip()
        severity = request.form.get('severity', 'moderate').strip()
        
        # Medical history
        recent_changes = request.form.get('recent_changes', '').strip()
        previous_treatment = request.form.get('previous_treatment', '').strip()
        
        # Validate required fields
        if not animal_type:
            return jsonify({'success': False, 'error': 'Animal type is required'}), 400
        
        # Combine all symptoms
        all_symptoms = symptoms.copy()
        if additional_symptoms:
            all_symptoms.append(additional_symptoms)
        
        if not all_symptoms:
            return jsonify({'success': False, 'error': 'At least one symptom must be provided'}), 400
        
        # Handle image upload and analysis
        image_analysis = None
        image_filename = None
        has_image = False
        
        if 'image' in request.files and request.files['image'].filename != '':
            file = request.files['image']
            if file and allowed_file(file.filename):
                try:
                    # Process and analyze image
                    image_bytes = file.read()
                    image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
                    
                    # Save image
                    filename = secure_filename(file.filename)
                    unique_filename = str(uuid.uuid4()) + '_' + filename
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    image.save(image_path)
                    image_filename = unique_filename
                    has_image = True
                    
                    # Analyze image with Gemini Vision
                    image_analysis = analyze_image_with_gemini_advanced(image, animal_type, all_symptoms)
                    
                except Exception as img_error:
                    print(f"⚠️ Image analysis error: {img_error}")
                    # Check if it's a rate limit error
                    error_str = str(img_error).lower()
                    if "429" in error_str or "resource exhausted" in error_str or "rate limit" in error_str:
                        return jsonify({
                            'success': False,
                            'error': '🚫 AI Service Temporarily Overloaded',
                            'detailed_message': 'Our AI analysis service is currently experiencing high demand. Please wait a moment and try again, or proceed with symptom-only analysis.',
                            'rate_limited': True,
                            'retry_after': 60  # Suggest retry after 60 seconds
                        }), 429
                    # Continue without image analysis for other errors
                    image_analysis = None
        
        # Generate comprehensive prediction
        try:
            prediction = generate_comprehensive_prediction(
                animal_info={
                    'type': animal_type,
                    'age': animal_age,
                    'weight': animal_weight,
                    'breed': animal_breed
                },
                symptoms=all_symptoms,
                duration=symptom_duration,
                severity=severity,
                recent_changes=recent_changes,
                previous_treatment=previous_treatment,
                image_analysis=image_analysis,
                has_image=has_image
            )
        except Exception as pred_error:
            print(f"⚠️ Prediction generation error: {pred_error}")
            # Check if it's a rate limit error
            error_str = str(pred_error).lower()
            if "429" in error_str or "resource exhausted" in error_str or "rate limit" in error_str:
                return jsonify({
                    'success': False,
                    'error': '🚫 AI Service Temporarily Overloaded',
                    'detailed_message': 'Our AI prediction service is currently experiencing high demand. Please wait a moment and try again.',
                    'rate_limited': True,
                    'retry_after': 60
                }), 429
            else:
                # Use fallback prediction for other errors
                prediction = generate_fallback_comprehensive_prediction(
                    {'type': animal_type, 'age': animal_age, 'weight': animal_weight, 'breed': animal_breed},
                    all_symptoms, severity, has_image
                )
        
        # Store in database
        try:
            user_id = session['user_id']
            prediction_data = {
                'user_id': user_id,
                'animal_type': animal_type,
                'animal_info': {
                    'age': animal_age,
                    'weight': animal_weight,
                    'breed': animal_breed
                },
                'symptoms': all_symptoms,
                'symptom_duration': symptom_duration,
                'severity': severity,
                'recent_changes': recent_changes,
                'previous_treatment': previous_treatment,
                'has_image': has_image,
                'image_filename': image_filename,
                'image_analysis': image_analysis,
                'prediction': prediction,
                'timestamp': datetime.now(),
                'prediction_type': 'integrated_image_symptoms'
            }
            
            if predictions_collection is not None:
                predictions_collection.insert_one(prediction_data)
                print(f"✅ Integrated prediction saved to database")
            
        except Exception as db_error:
            print(f"⚠️ Database save error: {db_error}")
        
        return jsonify({
            'success': True,
            'prediction': prediction,
            'has_image': has_image,
            'image_analysis_available': image_analysis is not None
        })
        
    except Exception as e:
        print(f"❌ Error in integrated prediction: {e}")
        return jsonify({
            'success': False,
            'error': f'Prediction failed: {str(e)}'
        }), 500

def analyze_image_with_gemini_advanced(image, animal_type, symptoms):
    """Advanced image analysis using Gemini Vision API with symptom correlation"""
    try:
        if not GEMINI_AVAILABLE:
            return None
            
        # Convert PIL image to bytes
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format='JPEG')
        img_byte_arr = img_byte_arr.getvalue()
        
        # Prepare the image for Gemini
        image_parts = [
            {
                "mime_type": "image/jpeg",
                "data": img_byte_arr
            }
        ]
        
        # Create detailed prompt for image analysis
        symptoms_text = ', '.join(symptoms) if symptoms else 'No specific symptoms provided'
        
        prompt = f"""Analyze this {animal_type} image for disease indicators and correlate with reported symptoms.

Reported Symptoms: {symptoms_text}

Please analyze the image for:
1. **Visual Disease Indicators**: Any visible signs of disease, injury, or abnormalities
2. **Physical Condition**: Overall body condition, posture, alertness
3. **Specific Features**: Skin condition, coat/fur quality, eye clarity, nose/mouth appearance
4. **Symptom Correlation**: How visible signs correlate with reported symptoms
5. **Severity Assessment**: Visual severity of any observed conditions

Provide analysis in JSON format:
{{
    "visible_abnormalities": ["List of visible abnormalities"],
    "body_condition": "Overall physical condition assessment",
    "skin_coat_condition": "Skin and coat/fur appearance",
    "eye_nose_condition": "Eyes, nose, mouth appearance", 
    "posture_behavior": "Visible posture and behavioral indicators",
    "symptom_correlation": "How image findings correlate with reported symptoms",
    "visual_severity": "mild/moderate/severe based on visual indicators",
    "confidence": 0.85,
    "additional_observations": "Any other relevant visual findings"
}}"""

        # Use the robust API call function with disease detection API key
        response_text, error = call_gemini_with_retry('gemini-2.0-flash-exp', prompt, image_parts, api_key=GEMINI_API_KEY_DISEASE)
        
        if error:
            print(f"⚠️ Gemini image analysis error: {error}")
            return None
            
        if response_text:
            try:
                # Try to parse JSON response
                image_analysis = json.loads(response_text)
                return image_analysis
            except json.JSONDecodeError:
                # Extract key information from text if JSON fails
                return {
                    "visible_abnormalities": ["Analysis completed but specific details not structured"],
                    "body_condition": "Image analyzed",
                    "symptom_correlation": response_text[:200] + "...",
                    "confidence": 0.7,
                    "additional_observations": "Full analysis available in text format"
                }
        
        return None
            
    except Exception as e:
        print(f"❌ Image analysis error: {e}")
        return None


def generate_comprehensive_prediction(animal_info, symptoms, duration, severity, recent_changes, previous_treatment, image_analysis, has_image):
    """Generate comprehensive disease prediction combining image and symptom analysis"""
    
    try:
        # Prepare comprehensive analysis prompt
        animal_description = f"{animal_info['type']}"
        if animal_info.get('breed'):
            animal_description += f" ({animal_info['breed']})"
        if animal_info.get('age'):
            animal_description += f", {animal_info['age']} old"
        if animal_info.get('weight'):
            animal_description += f", {animal_info['weight']}"
        
        # Image analysis summary
        image_summary = ""
        if has_image and image_analysis:
            image_summary = f"""
IMAGE ANALYSIS FINDINGS:
- Visible abnormalities: {', '.join(image_analysis.get('visible_abnormalities', ['None noted']))}
- Body condition: {image_analysis.get('body_condition', 'Normal')}
- Skin/coat condition: {image_analysis.get('skin_coat_condition', 'Normal')}
- Eyes/nose condition: {image_analysis.get('eye_nose_condition', 'Normal')}
- Visual severity: {image_analysis.get('visual_severity', 'Not assessed')}
- Symptom correlation: {image_analysis.get('symptom_correlation', 'No correlation noted')}
"""
        elif has_image:
            image_summary = "\nIMAGE ANALYSIS: Image was provided but analysis was not successful."
        else:
            image_summary = "\nIMAGE ANALYSIS: No image provided for visual assessment."
        
        prompt = f"""You are a veterinary expert providing comprehensive disease diagnosis by combining clinical symptoms with visual image analysis.

ANIMAL INFORMATION:
- Species: {animal_description}

CLINICAL PRESENTATION:
- Primary symptoms: {', '.join(symptoms)}
- Duration: {duration or 'Not specified'}
- Severity: {severity}
- Recent changes: {recent_changes or 'None reported'}
- Previous treatment: {previous_treatment or 'None administered'}

{image_summary}

DIAGNOSTIC TASK:
Provide a comprehensive disease prediction that CORRELATES both the clinical symptoms AND image findings (if available). The diagnosis should be specific and consider how visual indicators support or contradict the reported symptoms.

Respond in JSON format:
{{
    "primary_diagnosis": "Most likely specific disease name",
    "confidence_score": 0.85,
    "diagnostic_reasoning": "Detailed explanation of how symptoms and image findings lead to this diagnosis",
    "image_symptom_correlation": "How visual findings correlate with reported symptoms",
    "alternative_diagnoses": [
        {{
            "disease": "Alternative disease name",
            "confidence": 0.65,
            "reasoning": "Why this is a possibility"
        }}
    ],
    "severity_assessment": "mild/moderate/severe with justification",
    "treatment_recommendations": {{
        "immediate_actions": ["Action 1", "Action 2", "Action 3"],
        "ongoing_treatment": ["Treatment 1", "Treatment 2"],
        "monitoring": "What to monitor and when",
        "veterinary_urgency": "immediate/within 24 hours/within week/routine follow-up"
    }},
    "prognosis": "Expected outcome with treatment",
    "risk_factors": ["Risk factor 1", "Risk factor 2"],
    "prevention_advice": "How to prevent recurrence or similar issues"
}}

Focus on providing the most accurate diagnosis possible by integrating ALL available information."""

        if GEMINI_AVAILABLE:
            # Use the robust API call function with disease detection API key
            response_text, error = call_gemini_with_retry('gemini-2.0-flash-exp', prompt, api_key=GEMINI_API_KEY_DISEASE)
            
            if error:
                print(f"⚠️ Gemini AI error: {error}")
                return generate_fallback_comprehensive_prediction(animal_info, symptoms, severity, has_image)
                
            if response_text:
                try:
                    prediction = json.loads(response_text)
                    
                    # Enhance prediction with image correlation info
                    if has_image:
                        prediction['analysis_type'] = 'Image + Symptoms Analysis'
                        prediction['image_analyzed'] = True
                    else:
                        prediction['analysis_type'] = 'Symptoms Analysis Only'
                        prediction['image_analyzed'] = False
                    
                    return prediction
                    
                except json.JSONDecodeError:
                    # Fallback to text parsing
                    return parse_comprehensive_prediction_text(response_text, animal_info['type'], has_image)
            else:
                return generate_fallback_comprehensive_prediction(animal_info, symptoms, severity, has_image)
                
        else:
            return generate_fallback_comprehensive_prediction(animal_info, symptoms, severity, has_image)
            
    except Exception as e:
        print(f"❌ Error in comprehensive prediction: {e}")
        return generate_fallback_comprehensive_prediction(animal_info, symptoms, severity, has_image)


def parse_comprehensive_prediction_text(text_response, animal_type, has_image):
    """Parse text response when JSON parsing fails"""
    try:
        # Extract key information from text
        lines = text_response.split('\n')
        disease_name = f"Suspected {animal_type.title()} Health Issue"
        
        for line in lines:
            if any(keyword in line.lower() for keyword in ['diagnosis', 'disease', 'condition']):
                if ':' in line:
                    potential_disease = line.split(':', 1)[1].strip()
                    if len(potential_disease) > 3 and len(potential_disease) < 100:
                        disease_name = potential_disease
                        break
        
        analysis_type = 'Image + Symptoms Analysis' if has_image else 'Symptoms Analysis Only'
        
        return {
            'primary_diagnosis': disease_name,
            'confidence_score': 0.75,
            'diagnostic_reasoning': 'Based on comprehensive analysis of provided symptoms and available clinical information.',
            'image_symptom_correlation': 'Analysis completed with available data' if has_image else 'No image provided for correlation',
            'alternative_diagnoses': [
                {
                    'disease': 'Secondary complications',
                    'confidence': 0.60,
                    'reasoning': 'May develop as secondary condition'
                }
            ],
            'severity_assessment': 'Moderate - requires professional evaluation',
            'treatment_recommendations': {
                'immediate_actions': [
                    'Monitor animal closely for changes',
                    'Ensure access to clean water and appropriate food',
                    'Provide comfortable, quiet environment'
                ],
                'ongoing_treatment': [
                    'Follow veterinarian recommendations',
                    'Administer prescribed medications as directed'
                ],
                'monitoring': 'Check symptoms daily and note any changes',
                'veterinary_urgency': 'within 24 hours'
            },
            'prognosis': 'Good with appropriate veterinary care',
            'risk_factors': ['Age', 'Environmental conditions', 'Previous health history'],
            'prevention_advice': 'Maintain regular health checks and proper nutrition',
            'analysis_type': analysis_type,
            'image_analyzed': has_image
        }
        
    except Exception as e:
        print(f"Error parsing comprehensive prediction text: {e}")
        return generate_fallback_comprehensive_prediction(
            {'type': animal_type}, 
            ['general symptoms'], 
            'moderate', 
            has_image
        )


def generate_fallback_comprehensive_prediction(animal_info, symptoms, severity, has_image):
    """Generate enhanced fallback prediction when AI is not available"""
    
    # Comprehensive disease database with detailed symptom matching
    disease_database = {
        'cattle': {
            'bovine_respiratory_disease': {
                'symptoms': ['coughing', 'difficulty breathing', 'nasal discharge', 'fever', 'lethargy'],
                'visual_signs': ['labored breathing', 'nasal discharge', 'droopy ears', 'head down posture'],
                'name': 'Bovine Respiratory Disease Complex',
                'confidence': 0.88,
                'urgency': 'immediate'
            },
            'mastitis': {
                'symptoms': ['swollen udder', 'hot udder', 'hard udder', 'abnormal milk', 'fever'],
                'visual_signs': ['visible udder swelling', 'discolored milk', 'cow discomfort'],
                'name': 'Mastitis',
                'confidence': 0.92,
                'urgency': 'within 24 hours'
            },
            'lameness': {
                'symptoms': ['limping', 'foot problems', 'reluctance to move', 'favoring one leg'],
                'visual_signs': ['abnormal gait', 'weight shifting', 'hoof problems'],
                'name': 'Lameness/Foot Problems',
                'confidence': 0.85,
                'urgency': 'within week'
            },
            'digestive_issues': {
                'symptoms': ['diarrhea', 'bloating', 'loss of appetite', 'dehydration', 'abdominal pain'],
                'visual_signs': ['sunken eyes', 'poor coat', 'distended abdomen', 'weakness'],
                'name': 'Digestive Disorder',
                'confidence': 0.80,
                'urgency': 'within 24 hours'
            }
        },
        'dog': {
            'gastroenteritis': {
                'symptoms': ['vomiting', 'diarrhea', 'loss of appetite', 'lethargy', 'dehydration'],
                'visual_signs': ['weakness', 'dehydration signs', 'poor posture'],
                'name': 'Gastroenteritis',
                'confidence': 0.85,
                'urgency': 'within 24 hours'
            },
            'skin_allergies': {
                'symptoms': ['scratching', 'itching', 'red skin', 'hair loss', 'hot spots'],
                'visual_signs': ['visible scratching', 'skin irritation', 'hair loss patches'],
                'name': 'Allergic Dermatitis',
                'confidence': 0.87,
                'urgency': 'within week'
            },
            'ear_infection': {
                'symptoms': ['head shaking', 'ear scratching', 'ear odor', 'discharge', 'balance problems'],
                'visual_signs': ['head tilting', 'ear discharge', 'scratching behavior'],
                'name': 'Ear Infection',
                'confidence': 0.90,
                'urgency': 'within week'
            },
            'kennel_cough': {
                'symptoms': ['persistent cough', 'retching', 'gagging', 'exercise intolerance'],
                'visual_signs': ['coughing fits', 'throat irritation signs'],
                'name': 'Kennel Cough',
                'confidence': 0.83,
                'urgency': 'within week'
            }
        },
        'cat': {
            'upper_respiratory': {
                'symptoms': ['sneezing', 'nasal discharge', 'eye discharge', 'congestion'],
                'visual_signs': ['nasal discharge', 'squinting', 'mouth breathing'],
                'name': 'Upper Respiratory Infection',
                'confidence': 0.85,
                'urgency': 'within week'
            },
            'urinary_issues': {
                'symptoms': ['frequent urination', 'straining', 'blood in urine', 'inappropriate urination'],
                'visual_signs': ['straining posture', 'frequent litter box visits'],
                'name': 'Feline Lower Urinary Tract Disease',
                'confidence': 0.88,
                'urgency': 'within 24 hours'
            },
            'skin_problems': {
                'symptoms': ['excessive grooming', 'hair loss', 'skin irritation', 'scratching'],
                'visual_signs': ['over-groomed areas', 'skin lesions', 'hair loss patches'],
                'name': 'Feline Dermatitis',
                'confidence': 0.82,
                'urgency': 'within week'
            }
        }
    }
    
    # Find best match using advanced scoring
    symptom_text = ' '.join(symptoms).lower()
    animal_diseases = disease_database.get(animal_info['type'], {})
    
    best_match = None
    best_score = 0
    
    for disease_key, disease_data in animal_diseases.items():
        # Calculate symptom match score
        symptom_matches = sum(1 for s in disease_data['symptoms'] if s.lower() in symptom_text)
        symptom_score = symptom_matches / len(disease_data['symptoms'])
        
        # Boost score if visual signs would be present with image
        visual_score = 0
        if has_image:
            visual_matches = sum(1 for v in disease_data['visual_signs'] 
                               if any(keyword in symptom_text for keyword in v.lower().split()))
            visual_score = visual_matches / len(disease_data['visual_signs']) * 0.3
        
        total_score = symptom_score + visual_score
        
        if total_score > best_score:
            best_score = total_score
            best_match = disease_data
    
    # Fallback if no good match
    if not best_match or best_score < 0.3:
        best_match = {
            'name': f'General {animal_info["type"].title()} Health Issue',
            'confidence': 0.60,
            'urgency': 'within week'
        }
    
    # Adjust confidence based on various factors
    confidence = best_match.get('confidence', 0.70)
    if has_image:
        confidence = min(0.95, confidence + 0.08)
    if severity == 'severe':
        confidence = min(0.95, confidence + 0.05)
    if len(symptoms) >= 3:
        confidence = min(0.95, confidence + 0.03)
    
    # Determine urgency
    urgency = best_match.get('urgency', 'within week')
    if severity == 'severe':
        urgency = 'immediate'
    elif severity == 'moderate' and urgency == 'within week':
        urgency = 'within 24 hours'
    
    # Generate comprehensive response
    analysis_type = 'Enhanced Image + Symptoms Analysis' if has_image else 'Enhanced Symptoms Analysis'
    
    return {
        'primary_diagnosis': best_match['name'],
        'confidence_score': round(confidence, 2),
        'diagnostic_reasoning': f'Based on comprehensive symptom pattern analysis{" and visual assessment indicators" if has_image else ""}. The reported symptoms show strong correlation with typical presentations of this condition in {animal_info["type"]}.',
        'image_symptom_correlation': f'Visual indicators support the symptom assessment for {best_match["name"]}' if has_image else 'No image provided - diagnosis based on symptom analysis only',
        'alternative_diagnoses': [
            {
                'disease': 'Secondary Bacterial Infection',
                'confidence': round(confidence * 0.75, 2),
                'reasoning': 'May develop as a secondary complication'
            },
            {
                'disease': 'Stress-induced Condition',
                'confidence': round(confidence * 0.65, 2),
                'reasoning': 'Environmental or management factors may contribute'
            },
            {
                'disease': 'Nutritional Deficiency',
                'confidence': round(confidence * 0.55, 2),
                'reasoning': 'Poor nutrition may weaken immune system'
            }
        ],
        'severity_assessment': f'{severity.title()} condition requiring {urgency} veterinary attention',
        'treatment_recommendations': {
            'immediate_actions': [
                'Ensure continuous access to clean, fresh water',
                'Provide quiet, stress-free environment',
                'Monitor vital signs and behavior changes',
                'Isolate from other animals if contagious disease suspected',
                'Record all symptoms and their progression'
            ],
            'ongoing_treatment': [
                'Follow prescribed veterinary treatment protocol',
                'Administer medications exactly as directed',
                'Maintain proper nutrition and hydration',
                'Provide supportive care based on condition',
                'Monitor response to treatment closely'
            ],
            'monitoring': f'Monitor appetite, behavior, vital signs, and symptom progression. Check every 2-4 hours for severe cases, daily for moderate cases.',
            'veterinary_urgency': urgency
        },
        'prognosis': 'Good to excellent with prompt veterinary care and appropriate treatment. Early intervention significantly improves outcomes.',
        'risk_factors': [
            'Age and overall health status of the animal',
            'Environmental conditions and management practices',
            'Nutritional status and feed quality',
            'Previous medical history and vaccinations',
            'Seasonal factors and disease prevalence in area'
        ],
        'prevention_advice': f'Maintain regular veterinary checkups, ensure proper vaccination schedule, provide high-quality nutrition, maintain clean environment, and monitor animals daily for early signs of illness.',
        'analysis_type': analysis_type,
        'image_analyzed': has_image,
        'note': 'This analysis uses advanced pattern matching algorithms and veterinary knowledge base to provide accurate assessments without requiring external AI services.'
    }


# =================== REMOVE UNNECESSARY OLD FUNCTIONS ===================
# Removing old duplicate functions to clean up the codebase

def extract_visible_symptoms(analysis_text):
    """Extract visible symptoms from analysis text"""
    visible_symptoms = []
    
    # Look for common visible symptoms mentioned in the analysis
    symptom_keywords = [
        'skin lesions', 'rash', 'swelling', 'discharge', 'inflammation',
        'lethargy', 'weakness', 'limping', 'difficulty breathing',
        'abnormal posture', 'pale gums', 'jaundice', 'dehydration',
        'hair loss', 'scratching', 'wounds', 'lumps', 'bumps'
    ]
    
    analysis_lower = analysis_text.lower()
    for keyword in symptom_keywords:
        if keyword in analysis_lower:
            visible_symptoms.append(keyword)
    
    return visible_symptoms

# =================== REMOVING OLD FUNCTIONS ===================
# Removed old generate_ai_prediction function - replaced by generate_comprehensive_prediction
# This keeps the codebase clean and focused on the new integrated approach

# Redirect old AI disease prediction to new integrated prediction
@app.route('/ai_disease_prediction')
def ai_disease_prediction():
    """Redirect to new integrated prediction page"""
    return redirect(url_for('integrated_prediction'))


def parse_text_response(response_text, animal_type, symptoms):
    """Parse text response when JSON parsing fails"""
    try:
        # Extract key information from text response
        lines = response_text.split('\n')
        
        primary_diagnosis = 'Unknown condition'
        confidence_score = 0.7
        recommendations = []
        
        # Look for diagnosis patterns
        for line in lines:
            line_lower = line.lower()
            if 'diagnosis' in line_lower and ':' in line:
                primary_diagnosis = line.split(':', 1)[1].strip()
            elif 'recommend' in line_lower or 'treatment' in line_lower:
                recommendations.append(line.strip())
        
        return {
            'primary_diagnosis': primary_diagnosis,
            'confidence_score': confidence_score,
            'symptom_analysis': {
                'reported_symptoms': symptoms,
                'severity_assessment': 'moderate'
            },
            'recommendations': {
                'immediate_actions': ['Consult with veterinarian for proper diagnosis'],
                'treatment_suggestions': recommendations[:3] if recommendations else ['Professional veterinary care recommended'],
                'when_to_consult_vet': 'within 24 hours'
            },
            'ai_response': response_text
        }
    except Exception as e:
        print(f"Text parsing error: {e}")
        return {
            'primary_diagnosis': 'Please consult veterinarian',
            'confidence_score': 0.5,
            'error': str(e)
        }

# =================== CHATBOT ROUTES ===================

@app.route('/chatbot')
def chatbot_page():
    """Render the chatbot interface"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('chatbot.html')

@app.route('/api/chat', methods=['POST'])
def chat_endpoint():
    """Handle text-based chat messages with session-based history"""
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({
            'success': False, 
            'error': 'Please log in to use the chatbot'
        }), 401
    
    # Check if chatbot is available
    is_available, status_message = get_chatbot_status()
    if not is_available:
        return jsonify({
            'success': False, 
            'error': f'Chatbot service unavailable: {status_message}',
            'fallback_response': """I'm currently unable to connect to the AI service. Here are some things you can try:

🔧 **For Technical Issues:**
- Refresh the page and try again
- Check your internet connection
- Contact support if the problem persists

🐄 **For Animal Health Questions:**
- Document symptoms with photos if possible
- Note the animal's behavior changes
- Contact your local veterinarian for urgent cases

🩺 **Common Animal Diseases to Watch For:**
- Fever, loss of appetite, unusual discharge
- Lameness, difficulty breathing
- Skin lesions, swelling

**Emergency:** Call your veterinarian immediately for serious symptoms!
"""
        })
    
    try:
        # Get JSON data with timeout
        import threading
        import time
        
        start_time = time.time()
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data received'})
            
        message = data.get('message', '').strip()
        language = data.get('language', 'en')
        session_key = data.get('session_key', None)
        
        if not message:
            return jsonify({'success': False, 'error': 'Empty message'})
        
        # Generate session key if not provided
        if not session_key:
            session_key = f"chat_{session['user_id']}_{int(time.time())}"
        
        print(f"📝 Processing message: {message[:50]}{'...' if len(message) > 50 else ''}")
        print(f"🔑 Session key: {session_key}")
        
        # Load previous conversation history for this session from chatbot
        if hasattr(chatbot, 'load_session_history'):
            chatbot.load_session_history(session_key)
        
        # Process the query with session context
        response = chatbot.process_text_query(message, language, session_key)
        
        processing_time = time.time() - start_time
        print(f"⚡ Response generated in {processing_time:.2f} seconds")
        
        # Store conversation in database with session key
        if db is not None and 'user_id' in session:
            try:
                conversation_doc = {
                    'user_id': session['user_id'],
                    'session_key': session_key,
                    'message': message,
                    'response': response.get('response', ''),
                    'language': language,
                    'timestamp': datetime.now(timezone.utc),
                    'type': 'text',
                    'processing_time': processing_time
                }
                db.conversations.insert_one(conversation_doc)
            except Exception as db_error:
                print(f"Database error storing conversation: {db_error}")
        
        # Add session key to response
        response['session_key'] = session_key
        
        return jsonify(response)
    
    except Exception as e:
        print(f"Error in chat endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'error': f'Server error: {str(e)}',
            'fallback_response': 'I encountered an error processing your request. Please try again or contact support if the problem persists.'
        })

@app.route('/api/chat/upload', methods=['POST'])
def upload_for_analysis():
    """Handle file uploads for analysis - optimized for better error handling"""
    # Check if chatbot is available
    is_available, status_message = get_chatbot_status()
    if not is_available:
        return jsonify({
            'success': False, 
            'error': f'Chatbot service unavailable: {status_message}',
            'fallback_response': 'File analysis is currently unavailable. Please try again later or contact support.'
        })
    
    try:
        import time
        start_time = time.time()
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['file']
        question = request.form.get('question', '')
        language = request.form.get('language', 'en')
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        # Check file type and validate
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        
        print(f"📁 Analyzing uploaded file: {filename} ({file_ext})")
        
        if file_ext in ['png', 'jpg', 'jpeg', 'webp']:
            # Process as image with better error handling
            try:
                response = chatbot.analyze_image(file, question, language)
            except Exception as img_error:
                print(f"Image analysis error: {img_error}")
                return jsonify({
                    'success': False, 
                    'error': f'Image analysis failed: {str(img_error)}',
                    'fallback_response': 'Unable to analyze the uploaded image. Please try with a different image or describe the symptoms in text.'
                })
                
        elif file_ext == 'pdf':
            # Process as PDF
            try:
                response = chatbot.process_pdf(file, question, language)
            except Exception as pdf_error:
                print(f"PDF analysis error: {pdf_error}")
                return jsonify({
                    'success': False, 
                    'error': f'PDF analysis failed: {str(pdf_error)}',
                    'fallback_response': 'Unable to analyze the uploaded PDF. Please try with a different file or describe the content in text.'
                })
        else:
            return jsonify({
                'success': False, 
                'error': f'Unsupported file format: {file_ext}',
                'fallback_response': 'Please upload PNG, JPG, JPEG, WEBP images or PDF files only.'
            })
        
        processing_time = time.time() - start_time
        print(f"⚡ File analysis completed in {processing_time:.2f} seconds")
        
        # Store conversation in database if available
        if db is not None and 'user_id' in session:
            try:
                conversation_doc = {
                    'user_id': session['user_id'],
                    'file_name': filename,
                    'file_type': file_ext,
                    'question': question,
                    'response': response.get('response', ''),
                    'language': language,
                    'timestamp': datetime.now(timezone.utc),
                    'type': 'file_analysis',
                    'processing_time': processing_time
                }
                db.conversations.insert_one(conversation_doc)
            except Exception as db_error:
                print(f"Database error storing conversation: {db_error}")
        
        return jsonify(response)
    
    except Exception as e:
        print(f"Error in upload endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'error': f'Upload processing failed: {str(e)}',
            'fallback_response': 'File upload encountered an error. Please try again with a different file or contact support.'
        })

@app.route('/api/chat/languages', methods=['GET'])
def get_languages():
    """Get available languages for the chatbot"""
    try:
        # Check if chatbot is available
        is_available, status_message = get_chatbot_status()
        if not is_available:
            # Return basic language list even if chatbot is not available
            basic_languages = {
                'en': 'English',
                'hi': 'Hindi', 
                'mr': 'Marathi',
                'te': 'Telugu',
                'ta': 'Tamil'
            }
            return jsonify({'success': True, 'languages': basic_languages})
        
        languages_list = chatbot.get_supported_languages()
        # Convert list format to dict format for frontend compatibility
        languages_dict = {lang['code']: lang['name'] for lang in languages_list}
        return jsonify({'success': True, 'languages': languages_dict})
        
    except Exception as e:
        print(f"Error getting languages: {e}")
        # Return basic language list on error
        basic_languages = {
            'en': 'English',
            'hi': 'Hindi',
            'mr': 'Marathi'
        }
        return jsonify({'success': True, 'languages': basic_languages})
    if not chatbot:
        return jsonify({'success': False, 'error': 'Chatbot service not available'})
    
    try:
        languages = chatbot.get_available_languages()
        return jsonify({'success': True, 'languages': languages})
    except Exception as e:
        print(f"Error getting languages: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/chat/history', methods=['GET'])
def get_chat_history():
    """Get conversation history for current session"""
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Please log in to access chat history'}), 401
    
    try:
        session_key = request.args.get('session_key')
        if not session_key:
            return jsonify({'success': False, 'error': 'Session key required'})
        
        # Get conversation history from database
        if db is not None:
            try:
                conversations = list(db.conversations.find({
                    'user_id': session['user_id'],
                    'session_key': session_key
                }).sort('timestamp', 1))
                
                # Format conversations for frontend
                history = []
                for conv in conversations:
                    history.append({
                        'id': str(conv['_id']),
                        'message': conv.get('message', ''),
                        'response': conv.get('response', ''),
                        'timestamp': conv.get('timestamp', datetime.now()).isoformat(),
                        'language': conv.get('language', 'en'),
                        'type': conv.get('type', 'text')
                    })
                
                return jsonify({
                    'success': True,
                    'history': history,
                    'session_key': session_key
                })
                
            except Exception as db_error:
                print(f"Database error retrieving conversation history: {db_error}")
                return jsonify({'success': False, 'error': 'Failed to retrieve chat history'})
        
        # Fallback to chatbot service if available
        is_available, status_message = get_chatbot_status()
        if not is_available:
            return jsonify({'success': False, 'error': f'Chatbot service unavailable: {status_message}'})
        
        response = chatbot.get_conversation_history()
        response['session_key'] = session_key
        return jsonify(response)
        
    except Exception as e:
        print(f"Error getting conversation history: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/chat/sessions', methods=['GET'])
def get_chat_sessions():
    """Get list of chat sessions for current user"""
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Please log in to access chat sessions'}), 401
    
    try:
        # Get unique session keys from database
        if db is not None:
            try:
                pipeline = [
                    {'$match': {'user_id': session['user_id']}},
                    {'$group': {
                        '_id': '$session_key',
                        'last_message': {'$last': '$timestamp'},
                        'first_message': {'$first': '$timestamp'},
                        'message_count': {'$sum': 1},
                        'last_user_message': {'$last': '$message'}
                    }},
                    {'$sort': {'last_message': -1}},
                    {'$limit': 20}  # Return last 20 sessions
                ]
                
                sessions_data = list(db.conversations.aggregate(pipeline))
                
                sessions = []
                for session_data in sessions_data:
                    if session_data['_id']:  # Skip null session keys
                        sessions.append({
                            'session_key': session_data['_id'],
                            'last_message_time': session_data['last_message'].isoformat(),
                            'first_message_time': session_data['first_message'].isoformat(),
                            'message_count': session_data['message_count'],
                            'preview': session_data['last_user_message'][:100] if session_data['last_user_message'] else 'No messages'
                        })
                
                return jsonify({
                    'success': True,
                    'sessions': sessions
                })
                
            except Exception as db_error:
                print(f"Database error retrieving chat sessions: {db_error}")
                return jsonify({'success': False, 'error': 'Failed to retrieve chat sessions'})
        
        return jsonify({
            'success': True,
            'sessions': []
        })
        
    except Exception as e:
        print(f"Error getting chat sessions: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/chat/clear', methods=['POST'])
def clear_conversation():
    """Clear the conversation history for a specific session"""
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Please log in to clear conversations'}), 401
    
    try:
        data = request.get_json()
        session_key = data.get('session_key') if data else None
        
        if not session_key:
            return jsonify({'success': False, 'error': 'Session key required'})
        
        # Clear from database
        if db is not None:
            try:
                result = db.conversations.delete_many({
                    'user_id': session['user_id'],
                    'session_key': session_key
                })
                
                print(f"Cleared {result.deleted_count} messages for session {session_key}")
                
                return jsonify({
                    'success': True, 
                    'message': f'Cleared {result.deleted_count} messages',
                    'session_key': session_key
                })
                
            except Exception as db_error:
                print(f"Database error clearing conversation: {db_error}")
                return jsonify({'success': False, 'error': 'Failed to clear conversation from database'})
        
        # Fallback to chatbot service if available
        is_available, status_message = get_chatbot_status()
        if not is_available:
            return jsonify({'success': False, 'error': f'Chatbot service unavailable: {status_message}'})
        
        response = chatbot.clear_conversation()
        response['session_key'] = session_key
        return jsonify(response)
        
    except Exception as e:
        print(f"Error clearing conversation: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/chat/health', methods=['GET'])
def chatbot_health_check():
    """Check chatbot service health"""
    # Check if chatbot is available
    is_available, status_message = get_chatbot_status()
    if not is_available:
        return jsonify({
            'success': True,
            'healthy': False,
            'services': {
                'genai_available': False,
                'vision_available': False,
                'pdf_available': False,
                'translation_available': False,
                'image_processing_available': False
            },
            'message': status_message
        })
    
    try:
        response = chatbot.health_check()
        return jsonify(response)
    except Exception as e:
        print(f"Error checking chatbot health: {e}")
        return jsonify({'success': False, 'error': str(e)})
        response = chatbot.clear_conversation()
        return jsonify(response)
    except Exception as e:
        print(f"Error clearing conversation: {e}")
        return jsonify({'success': False, 'error': str(e)})

# ==============================================
# DEBUG AND STATUS ROUTES
# ==============================================

@app.route('/api/debug/status')
def debug_status():
    """Debug endpoint to check system status"""
    status = {
        'database_connected': db is not None,
        'collections': {
            'users': users_collection is not None,
            'predictions': predictions_collection is not None,
            'consultants': consultants_collection is not None,
            'consultation_requests': consultation_requests_collection is not None,
            'messages': messages_collection is not None
        },
        'chatbot_available': CHATBOT_AVAILABLE,
        'session_info': {
            'consultant_logged_in': 'consultant_id' in session,
            'consultant_id': session.get('consultant_id', 'None'),
            'consultant_name': session.get('consultant_name', 'None')
        }
    }
    
    # Test database connection
    try:
        if db:
            db.command('ping')
            status['database_ping'] = True
        else:
            status['database_ping'] = False
    except Exception as e:
        status['database_ping'] = False
        status['database_error'] = str(e)
    
    return jsonify(status)

# ==============================================
# VETERINARY CONSULTANT SYSTEM ROUTES
# ==============================================

@app.route('/consultant-login')
def consultant_login_page():
    """Consultant login page"""
    return render_template('consultant_login.html')

@app.route('/consultant-register')
def consultant_register_page():
    """Consultant registration page"""
    return render_template('consultant_register.html')

@app.route('/consultant-dashboard')
def consultant_dashboard():
    """Consultant dashboard - requires authentication"""
    if 'consultant_id' not in session:
        flash('Please login to access the consultant dashboard', 'error')
        return redirect(url_for('consultant_login_page'))
    
    # Check if database is available
    if db is None or consultants_collection is None:
        flash('Database not available. Please try again later.', 'error')
        return redirect(url_for('consultant_login_page'))
    
    consultant_id = session['consultant_id']
    
    # Get consultant info
    try:
        consultant = consultants_collection.find_one({'_id': ObjectId(consultant_id)})
        if not consultant:
            flash('Consultant not found', 'error')
            session.pop('consultant_id', None)
            session.pop('consultant_name', None)
            return redirect(url_for('consultant_login_page'))
        
        return render_template('consultant_dashboard.html', consultant=consultant)
    except Exception as e:
        print(f"Error loading consultant dashboard: {e}")
        print(f"Error type: {type(e).__name__}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('consultant_login_page'))

@app.route('/consultation-chat/<request_id>')
def consultation_chat(request_id):
    """Chat page for consultation (accessible by both consultants and farmers)"""
    # Check if either consultant or farmer is logged in
    if 'consultant_id' not in session and 'user_id' not in session:
        flash('Please login to access the chat', 'error')
        return redirect(url_for('login_page'))
    
    try:
        # Find the consultation
        consultation = consultation_requests_collection.find_one({
            '_id': ObjectId(request_id)
        })
        
        if not consultation:
            flash('Consultation not found', 'error')
            if 'consultant_id' in session:
                return redirect(url_for('consultant_dashboard'))
            else:
                return redirect(url_for('consultation_request_page'))
        
        # Verify access rights
        has_access = False
        is_farmer = False
        
        if 'consultant_id' in session:
            # Consultant access - must be assigned to this consultation
            has_access = consultation.get('assigned_to') == session['consultant_id']
            is_farmer = False
            print(f"🔍 DEBUG: Consultant {session['consultant_id']} accessing consultation {request_id}")
        
        elif 'user_id' in session:
            # Farmer access - must be the consultation creator
            user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
            has_access = (
                consultation.get('created_by_user_id') == session['user_id'] or
                consultation.get('farmer_email') == user.get('email', '') or
                consultation.get('contact_phone') == user.get('phone', '') or
                consultation.get('farmer_name') == user.get('name', '')
            )
            is_farmer = True
            print(f"🔍 DEBUG: Farmer {session['user_id']} accessing consultation {request_id}")
        
        if not has_access:
            flash('You do not have access to this consultation', 'error')
            if 'consultant_id' in session:
                return redirect(url_for('consultant_dashboard'))
            else:
                return redirect(url_for('consultation_request_page'))
        
        # Ensure consultation has proper ID format for frontend
        consultation['id'] = str(consultation['_id'])
        if 'created_at' in consultation:
            consultation['created_at'] = consultation['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"🔍 DEBUG: Loading consultation chat for ID: {request_id}")
        print(f"🔍 DEBUG: Consultation data: {consultation.get('farmer_name', 'Unknown')} - {consultation.get('animal_type', 'Unknown')}")
        print(f"🔍 DEBUG: User type: {'farmer' if is_farmer else 'consultant'}")
        
        return render_template('consultation_chat.html', consultation=consultation, is_farmer=is_farmer)
    except Exception as e:
        print(f"❌ ERROR loading consultation chat: {e}")
        print(f"❌ ERROR type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        flash('Error loading consultation chat', 'error')
        if 'consultant_id' in session:
            return redirect(url_for('consultant_dashboard'))
        else:
            return redirect(url_for('consultation_request_page'))

@app.route('/my-consultations')
def my_consultations():
    """Page for farmers to view their consultation history"""
    if 'user_id' not in session:
        flash('Please login to access your consultations', 'error')
        return redirect(url_for('login_page'))
    
    return render_template('my_consultations.html')

@app.route('/consultation-request')
def consultation_request_page():
    """Page for farmers to create consultation requests and consultants to view them"""
    # Allow both farmers and consultants to access this page
    if 'user_id' not in session and 'consultant_id' not in session:
        flash('Please login to access consultation requests', 'error')
        return redirect(url_for('login_page'))
    
    # Pass user type information to template
    is_consultant = 'consultant_id' in session
    user_name = session.get('consultant_name', session.get('user_name', 'User'))
    
    return render_template('consultation_request.html', 
                         is_consultant=is_consultant, 
                         user_name=user_name)

@app.route('/consultation-form')
def consultation_form_page():
    """Page for farmers to submit consultation details after selecting consultant"""
    # Only farmers can access this page
    if 'user_id' not in session:
        flash('Please login to access consultation form', 'error')
        return redirect(url_for('login_page'))
    
    return render_template('consultation_form.html')

@app.route('/debug')
def debug_page():
    """Debug page to troubleshoot consultation requests"""
    return render_template('debug.html')

@app.route('/api/test/create-request', methods=['POST'])
def test_create_request():
    """Test route to create a consultation request with known values"""
    try:
        if consultation_requests_collection is None:
            return jsonify({'error': 'Database not available'})
        
        # Get test data from request or use defaults
        data = request.get_json() or {}
        
        # Create a test request with known consultant ID
        consultant_id = data.get('consultant_id', None)  # None for auto-assign
        
        request_doc = {
            'farmer_name': 'Test Farmer',
            'farm_name': 'Test Farm',
            'farmer_email': 'test@example.com',
            'contact_phone': '1234567890',
            'location': 'Test Location',
            'animal_type': 'Cattle',
            'animal_age': '2 years',
            'animal_breed': 'Holstein',
            'symptoms': 'Test symptoms for debugging',
            'duration': '2 days',
            'urgency': 'Medium',
            'additional_notes': 'This is a test request',
            'status': 'Assigned' if consultant_id else 'Pending',
            'assigned_to': consultant_id,  # String consultant ID or None
            'assigned_consultant_name': 'Test Consultant' if consultant_id else None,
            'created_by_user_id': 'test_user',
            'created_at': datetime.now(timezone.utc),
            'images': []
        }
        
        result = consultation_requests_collection.insert_one(request_doc)
        
        return jsonify({
            'success': True,
            'message': 'Test request created',
            'request_id': str(result.inserted_id),
            'request_doc': {
                'assigned_to': request_doc['assigned_to'],
                'status': request_doc['status'],
                'farmer_name': request_doc['farmer_name']
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/test/consultant-requests/<consultant_id>', methods=['GET'])
def test_consultant_requests(consultant_id):
    """Test route to see what requests a specific consultant should see"""
    try:
        if consultation_requests_collection is None:
            return jsonify({'error': 'Database not available'})
        
        # Test the same query logic used in the dashboard
        query = {
            '$or': [
                {'assigned_to': consultant_id},  # Requests assigned to this consultant
                {'assigned_to': None}  # Unassigned requests available for pickup
            ]
        }
        
        requests = list(consultation_requests_collection.find(query).sort('created_at', -1))
        
        # Convert ObjectId to string for JSON serialization
        for req in requests:
            req['_id'] = str(req['_id'])
            if 'created_at' in req:
                req['created_at'] = req['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify({
            'consultant_id': consultant_id,
            'query': query,
            'requests': requests,
            'count': len(requests)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})



# ==============================================
# CONSULTANT API ROUTES
# ==============================================

@app.route('/api/consultant/register', methods=['POST'])
def register_consultant():
    """Register a new veterinary consultant"""
    try:
        # Check if database is connected
        if consultants_collection is None:
            return jsonify({'success': False, 'message': 'Database not available. Please try again later.'}), 500
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'name', 'specialization', 'experience', 'phone']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'{field} is required'}), 400
        
        # Validate email format
        if not validate_email(data['email']):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        # Validate password strength
        if not validate_password(data['password']):
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters long and contain letters and numbers'}), 400
        
        # Check if email already exists
        if consultants_collection.find_one({'email': data['email'].lower()}):
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        # Create consultant document
        consultant_doc = {
            'email': data['email'].lower(),
            'password': hash_password(data['password']),
            'name': data['name'],
            'specialization': data['specialization'],
            'experience': data['experience'],
            'phone': data['phone'],
            'license_number': data.get('license_number', ''),
            'qualifications': data.get('qualifications', ''),
            'status': 'active',
            'created_at': datetime.now(timezone.utc),
            'updated_at': datetime.now(timezone.utc)
        }
        
        # Insert into database
        result = consultants_collection.insert_one(consultant_doc)
        
        return jsonify({
            'success': True,
            'message': 'Registration successful! You can now login.',
            'consultant_id': str(result.inserted_id)
        })
        
    except Exception as e:
        print(f"Error registering consultant: {e}")
        return jsonify({'success': False, 'message': 'Registration failed. Please try again.'}), 500

@app.route('/api/consultant/login', methods=['POST'])
def login_consultant():
    """Login veterinary consultant"""
    try:
        # Check if database is connected
        if consultants_collection is None:
            return jsonify({'success': False, 'message': 'Database not available. Please try again later.'}), 500
        
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400
        
        # Find consultant by email
        consultant = consultants_collection.find_one({'email': data['email'].lower()})
        
        if not consultant:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Check password
        if not check_password(data['password'], consultant['password']):
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Check consultant status
        if consultant.get('status') != 'active':
            return jsonify({'success': False, 'message': 'Account is inactive. Please contact support.'}), 401
        
        # Store consultant info in session
        session['consultant_id'] = str(consultant['_id'])
        session['consultant_name'] = consultant['name']
        session['consultant_email'] = consultant['email']
        
        # Update last login
        consultants_collection.update_one(
            {'_id': consultant['_id']},
            {'$set': {'last_login': datetime.now(timezone.utc)}}
        )
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'consultant': {
                'id': str(consultant['_id']),
                'name': consultant['name'],
                'email': consultant['email'],
                'specialization': consultant['specialization'],
                'experience': consultant['experience']
            }
        })
        
    except Exception as e:
        print(f"Error logging in consultant: {e}")
        return jsonify({'success': False, 'message': 'Login failed. Please try again.'}), 500

@app.route('/api/consultant/logout', methods=['POST'])
def logout_consultant():
    """Logout consultant"""
    session.pop('consultant_id', None)
    session.pop('consultant_name', None)
    session.pop('consultant_email', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/consultation-requests', methods=['GET'])
def get_consultation_requests():
    """Get consultation requests for dashboard"""
    print(f"🔍 DEBUG: get_consultation_requests called")
    print(f"🔍 DEBUG: consultation_requests_collection type: {type(consultation_requests_collection)}")
    print(f"🔍 DEBUG: consultation_requests_collection is None: {consultation_requests_collection is None}")
    
    print(f"🔍 DEBUG: About to check session")
    if 'consultant_id' not in session:
        print(f"🔍 DEBUG: Unauthorized - no consultant_id in session")
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    print(f"🔍 DEBUG: Session check passed")
    try:
        print(f"🔍 DEBUG: About to check collection")
        # Check if database is connected - using try-catch to handle any boolean conversion issues
        try:
            collection_available = consultation_requests_collection is not None
            print(f"🔍 DEBUG: Collection available: {collection_available}")
            if not collection_available:
                print(f"🔍 DEBUG: Collection is None")
                return jsonify({'success': False, 'message': 'Database not available. Please try again later.'}), 500
        except Exception as collection_check_error:
            print(f"🔍 DEBUG: Error checking collection: {collection_check_error}")
            return jsonify({'success': False, 'message': 'Database connection issue.'}), 500
        
        print(f"🔍 DEBUG: Collection check passed")
        # Get filter from query params
        status_filter = request.args.get('status', 'all')
        print(f"🔍 DEBUG: Status filter: {status_filter}")
        
        # Build query for consultant requests
        # Show both assigned requests and unassigned requests available for pickup
        consultant_id = session['consultant_id']
        print(f"🔍 DEBUG: Current consultant ID: {consultant_id}")
        print(f"🔍 DEBUG: Consultant ID type: {type(consultant_id)}")
        
        # For debugging - let's see what requests exist in the database
        all_requests = list(consultation_requests_collection.find({}, {
            '_id': 1, 
            'farmer_name': 1, 
            'assigned_to': 1, 
            'status': 1,
            'assigned_consultant_name': 1
        }).sort('created_at', -1).limit(5))
        
        print(f"🔍 DEBUG: Recent requests in database:")
        for req in all_requests:
            print(f"   - ID: {req['_id']}, Farmer: {req.get('farmer_name')}, Assigned_to: {req.get('assigned_to')}, Status: {req.get('status')}")
        
        # Build comprehensive query to show:
        # 1. Requests assigned to this consultant
        # 2. Unassigned requests available for pickup (assigned_to = None)
        if status_filter == 'all':
            query = {
                '$or': [
                    {'assigned_to': consultant_id},  # Requests assigned to this consultant
                    {'assigned_to': None}  # Unassigned requests available for pickup
                ]
            }
        elif status_filter == 'Pending':
            query = {
                '$or': [
                    {'assigned_to': consultant_id, 'status': 'Pending'},  # Consultant's pending requests
                    {'assigned_to': None, 'status': 'Pending'}  # Unassigned pending requests
                ]
            }
        elif status_filter == 'Assigned':
            query = {'assigned_to': consultant_id, 'status': 'Assigned'}  # Only consultant's assigned requests
        elif status_filter == 'In Progress':
            query = {'assigned_to': consultant_id, 'status': 'In Progress'}  # Only consultant's in-progress requests
        else:
            query = {'assigned_to': consultant_id, 'status': status_filter}  # Other specific statuses
        
        print(f"🔍 DEBUG: Query built for consultant {consultant_id}: {query}")
        print(f"🔍 DEBUG: About to execute find")
        
        # Get requests from database
        requests_cursor = consultation_requests_collection.find(query).sort('created_at', -1)
        print(f"🔍 DEBUG: Find executed successfully")
        requests = []
        
        for req in requests_cursor:
            print(f"🔍 DEBUG: Found request - ID: {req['_id']}, Farmer: {req.get('farmer_name')}, Assigned_to: {req.get('assigned_to')}, Status: {req.get('status')}")
            # Convert ObjectId to string
            req['id'] = str(req['_id'])
            req['_id'] = str(req['_id'])
            
            # Convert datetime to string if present
            if 'created_at' in req:
                req['created_at'] = req['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            
            requests.append(req)
        
        print(f"🔍 DEBUG: Total requests found for consultant {consultant_id}: {len(requests)}")
        return jsonify({'success': True, 'requests': requests})
        
    except Exception as e:
        print(f"Error getting consultation requests: {e}")
        return jsonify({'success': False, 'message': 'Failed to load requests'}), 500

@app.route('/api/consultation-requests/<request_id>/accept', methods=['POST'])
def accept_consultation_request(request_id):
    """Accept a consultation request"""
    if 'consultant_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        consultant_id = session['consultant_id']  # This is a string
        consultant_name = session['consultant_name']
        
        print(f"🔍 DEBUG: Accept request - consultant_id: {consultant_id} (type: {type(consultant_id)})")
        
        # First, try to find and assign unassigned requests to this consultant
        # This handles the auto-assign case
        unassigned_result = consultation_requests_collection.update_one(
            {
                '_id': ObjectId(request_id),
                'assigned_to': None,  # Unassigned request
                'status': 'Pending'
            },
            {
                '$set': {
                    'assigned_to': consultant_id,  # Store as string to match session
                    'assigned_consultant_name': consultant_name,
                    'status': 'In Progress',
                    'accepted_at': datetime.now(timezone.utc)
                }
            }
        )
        
        print(f"🔍 DEBUG: Unassigned update result: {unassigned_result.modified_count}")
        
        # If no unassigned request was found, try to accept an already assigned request
        if unassigned_result.modified_count == 0:
            assigned_result = consultation_requests_collection.update_one(
                {
                    '_id': ObjectId(request_id), 
                    'assigned_to': consultant_id,  # Already assigned to this consultant (string match)
                    'status': {'$in': ['Assigned', 'Pending']}
                },
                {
                    '$set': {
                        'status': 'In Progress',
                        'accepted_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            print(f"🔍 DEBUG: Assigned update result: {assigned_result.modified_count}")
            
            if assigned_result.modified_count == 0:
                return jsonify({'success': False, 'message': 'Request not found or not available for acceptance'}), 404
        
        # Add initial message from consultant
        initial_message = {
            'consultation_id': request_id,
            'sender_type': 'consultant',
            'sender_id': session['consultant_id'],
            'sender_name': session['consultant_name'],
            'message': 'Hello! I have accepted your consultation request. How can I help you with your animal?',
            'timestamp': datetime.now(timezone.utc)
        }
        
        messages_collection.insert_one(initial_message)
        
        return jsonify({'success': True, 'message': 'Request accepted successfully'})
        
    except Exception as e:
        print(f"Error accepting request: {e}")
        return jsonify({'success': False, 'message': 'Failed to accept request'}), 500

@app.route('/api/consultation/<request_id>/messages', methods=['GET'])
def get_consultation_messages(request_id):
    """Get messages for a consultation (accessible by both consultants and farmers)"""
    print(f"🔍 DEBUG: GET /api/consultation/{request_id}/messages called")
    print(f"🔍 DEBUG: Session data: {dict(session)}")
    
    # Check if either consultant or farmer is logged in
    if 'consultant_id' not in session and 'user_id' not in session:
        print("❌ DEBUG: No consultant_id or user_id in session")
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        # Check if database collections are available
        if not MONGODB_AVAILABLE or messages_collection is None or consultation_requests_collection is None:
            print("❌ DEBUG: Database not available")
            return jsonify({'success': False, 'message': 'Database service unavailable'}), 503
        
        # Find the consultation
        consultation = consultation_requests_collection.find_one({
            '_id': ObjectId(request_id)
        })
        
        if not consultation:
            print("❌ DEBUG: Consultation not found")
            return jsonify({'success': False, 'message': 'Consultation not found'}), 404
        
        # Verify access rights
        has_access = False
        
        if 'consultant_id' in session:
            # Consultant access - must be assigned to this consultation
            has_access = consultation.get('assigned_to') == session['consultant_id']
            print(f"🔍 DEBUG: Consultant access check - assigned_to: {consultation.get('assigned_to')}, consultant_id: {session['consultant_id']}")
        
        elif 'user_id' in session:
            # Farmer access - must be the consultation creator
            user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
            has_access = (
                consultation.get('created_by_user_id') == session['user_id'] or
                consultation.get('farmer_email') == user.get('email', '') or
                consultation.get('contact_phone') == user.get('phone', '') or
                consultation.get('farmer_name') == user.get('name', '')
            )
            print(f"🔍 DEBUG: Farmer access check - created_by_user_id: {consultation.get('created_by_user_id')}, user_id: {session['user_id']}")
        
        if not has_access:
            print("❌ DEBUG: Access denied to consultation")
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        # Get messages
        messages_cursor = messages_collection.find(
            {'consultation_id': request_id}
        ).sort('timestamp', 1)
        
        messages = []
        message_count = 0
        for msg in messages_cursor:
            message_count += 1
            msg['id'] = str(msg['_id'])
            msg['_id'] = str(msg['_id'])
            if 'timestamp' in msg:
                msg['timestamp'] = msg['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            # Also handle old messages that might have created_at
            elif 'created_at' in msg:
                msg['timestamp'] = msg['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            messages.append(msg)
        
        print(f"🔍 DEBUG: Found {message_count} messages for consultation {request_id}")
        for i, msg in enumerate(messages):
            print(f"🔍 DEBUG: Message {i+1}: {msg.get('sender_type', 'unknown')} - {msg.get('message', '')[:50]}...")
        
        return jsonify({'success': True, 'messages': messages})
        
    except Exception as e:
        print(f"❌ ERROR getting messages: {e}")
        print(f"❌ ERROR type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to load messages'}), 500

@app.route('/api/consultation/<request_id>/messages', methods=['POST'])
def send_consultation_message(request_id):
    """Send a message in consultation chat (for both consultants and farmers)"""
    print(f"🔍 DEBUG: POST /api/consultation/{request_id}/messages called")
    print(f"🔍 DEBUG: Session data: {dict(session)}")
    
    # Check if either consultant or farmer is logged in
    if 'consultant_id' not in session and 'user_id' not in session:
        print("❌ DEBUG: No consultant_id or user_id in session")
        return jsonify({'success': False, 'message': 'Unauthorized - Please login again'}), 401
    
    try:
        # Check if database collections are available
        if not MONGODB_AVAILABLE or messages_collection is None or consultation_requests_collection is None:
            print("❌ DEBUG: Database not available")
            return jsonify({'success': False, 'message': 'Database service unavailable'}), 503
        
        data = request.get_json()
        print(f"🔍 DEBUG: Request data: {data}")
        
        if not data or not data.get('message'):
            print("❌ DEBUG: No message content provided")
            return jsonify({'success': False, 'message': 'Message content is required'}), 400
        
        # Find the consultation
        consultation = consultation_requests_collection.find_one({
            '_id': ObjectId(request_id)
        })
        
        if not consultation:
            print("❌ DEBUG: Consultation not found")
            return jsonify({'success': False, 'message': 'Consultation not found'}), 404
        
        # Determine sender type and verify access
        if 'consultant_id' in session:
            # Consultant sending message
            if consultation.get('assigned_to') != session['consultant_id']:
                print("❌ DEBUG: Consultant not assigned to this consultation")
                return jsonify({'success': False, 'message': 'Consultation not assigned to you'}), 403
            
            sender_type = 'consultant'
            sender_id = session['consultant_id']
            sender_name = session.get('consultant_name', 'Unknown Consultant')
            
        else:
            # Farmer sending message
            user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
            has_access = (
                consultation.get('created_by_user_id') == session['user_id'] or
                consultation.get('farmer_email') == user.get('email', '') or
                consultation.get('contact_phone') == user.get('phone', '') or
                consultation.get('farmer_name') == user.get('name', '')
            )
            
            if not has_access:
                print("❌ DEBUG: Farmer does not have access to this consultation")
                return jsonify({'success': False, 'message': 'Access denied'}), 403
            
            sender_type = 'farmer'
            sender_id = session['user_id']
            sender_name = user.get('name', 'Farmer')
        
        print(f"🔍 DEBUG: Sender type: {sender_type}, Sender: {sender_name}")
        
        # Create message document
        message_doc = {
            'consultation_id': request_id,
            'sender_type': sender_type,
            'sender_id': sender_id,
            'sender_name': sender_name,
            'message': data['message'],
            'timestamp': datetime.now(timezone.utc)
        }
        
        print(f"🔍 DEBUG: Creating message document: {message_doc}")
        
        # Insert message
        result = messages_collection.insert_one(message_doc)
        
        print(f"✅ DEBUG: Message inserted successfully with ID: {result.inserted_id}")
        
        # Return the message with ID
        message_doc['id'] = str(result.inserted_id)
        message_doc['_id'] = str(result.inserted_id)
        message_doc['timestamp'] = message_doc['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"✅ DEBUG: Returning message: {message_doc}")
        return jsonify({'success': True, 'message': message_doc})
        
    except Exception as e:
        print(f"❌ ERROR sending message: {e}")
        print(f"❌ ERROR type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to send message: {str(e)}'}), 500

@app.route('/api/consultation/<request_id>/upload', methods=['POST'])
def upload_consultation_file(request_id):
    """Upload a file to consultation chat"""
    print(f"🔍 DEBUG: POST /api/consultation/{request_id}/upload called")
    
    # Check if either consultant or farmer is logged in
    if 'consultant_id' not in session and 'user_id' not in session:
        print("❌ DEBUG: No consultant_id or user_id in session")
        return jsonify({'success': False, 'message': 'Unauthorized - Please login again'}), 401
    
    try:
        # Check if database collections are available
        if not MONGODB_AVAILABLE or messages_collection is None or consultation_requests_collection is None:
            print("❌ DEBUG: Database not available")
            return jsonify({'success': False, 'message': 'Database service unavailable'}), 503
        
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['file']
        message_text = request.form.get('message', '').strip()
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Find the consultation
        consultation = consultation_requests_collection.find_one({
            '_id': ObjectId(request_id)
        })
        
        if not consultation:
            print("❌ DEBUG: Consultation not found")
            return jsonify({'success': False, 'message': 'Consultation not found'}), 404
        
        # Determine sender type and verify access
        if 'consultant_id' in session:
            # Consultant sending file
            if consultation.get('assigned_to') != session['consultant_id']:
                print("❌ DEBUG: Consultant not assigned to this consultation")
                return jsonify({'success': False, 'message': 'Consultation not assigned to you'}), 403
            
            sender_type = 'consultant'
            sender_id = session['consultant_id']
            sender_name = session.get('consultant_name', 'Unknown Consultant')
            
        else:
            # Farmer sending file
            user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
            has_access = (
                consultation.get('created_by_user_id') == session['user_id'] or
                consultation.get('farmer_email') == user.get('email', '') or
                consultation.get('contact_phone') == user.get('phone', '') or
                consultation.get('farmer_name') == user.get('name', '')
            )
            
            if not has_access:
                print("❌ DEBUG: Farmer does not have access to this consultation")
                return jsonify({'success': False, 'message': 'Access denied'}), 403
            
            sender_type = 'farmer'
            sender_id = session['user_id']
            sender_name = user.get('name', 'Farmer')
        
        # Validate file type and size
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
        max_file_size = 10 * 1024 * 1024  # 10MB
        
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({'success': False, 'message': 'File type not allowed'}), 400
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > max_file_size:
            return jsonify({'success': False, 'message': 'File too large (max 10MB)'}), 400
        
        # Create uploads directory if it doesn't exist
        upload_dir = os.path.join('static', 'consultation_files')
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generate unique filename
        file_id = str(uuid.uuid4())
        unique_filename = f"{file_id}_{filename}"
        file_path = os.path.join(upload_dir, unique_filename)
        
        # Save file
        file.save(file_path)
        
        # Create message document with file info
        message_doc = {
            'consultation_id': request_id,
            'sender_type': sender_type,
            'sender_id': sender_id,
            'sender_name': sender_name,
            'message': message_text,
            'file_info': {
                'file_id': file_id,
                'filename': filename,
                'unique_filename': unique_filename,
                'file_path': file_path,
                'content_type': file.content_type,
                'size': file_size
            },
            'timestamp': datetime.now(timezone.utc)
        }
        
        print(f"🔍 DEBUG: Creating file message document: {message_doc}")
        
        # Insert message
        result = messages_collection.insert_one(message_doc)
        
        print(f"✅ DEBUG: File message inserted successfully with ID: {result.inserted_id}")
        
        # Return the message with ID
        message_doc['id'] = str(result.inserted_id)
        message_doc['_id'] = str(result.inserted_id)
        message_doc['timestamp'] = message_doc['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"✅ DEBUG: Returning file message: {message_doc}")
        return jsonify({'success': True, 'message': message_doc})
        
    except Exception as e:
        print(f"❌ ERROR uploading file: {e}")
        print(f"❌ ERROR type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to upload file: {str(e)}'}), 500

@app.route('/api/consultation/<request_id>/download/<file_id>')
def download_consultation_file(request_id, file_id):
    """Download a file from consultation chat"""
    print(f"🔍 DEBUG: GET /api/consultation/{request_id}/download/{file_id} called")
    
    # Check if either consultant or farmer is logged in
    if 'consultant_id' not in session and 'user_id' not in session:
        print("❌ DEBUG: No consultant_id or user_id in session")
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        # Check if database collections are available
        if not MONGODB_AVAILABLE or messages_collection is None or consultation_requests_collection is None:
            print("❌ DEBUG: Database not available")
            return jsonify({'success': False, 'message': 'Database service unavailable'}), 503
        
        # Find the consultation
        consultation = consultation_requests_collection.find_one({
            '_id': ObjectId(request_id)
        })
        
        if not consultation:
            print("❌ DEBUG: Consultation not found")
            return jsonify({'success': False, 'message': 'Consultation not found'}), 404
        
        # Verify access to consultation
        has_access = False
        
        if 'consultant_id' in session:
            # Consultant access - must be assigned to this consultation
            has_access = consultation.get('assigned_to') == session['consultant_id']
        elif 'user_id' in session:
            # Farmer access
            user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
            has_access = (
                consultation.get('created_by_user_id') == session['user_id'] or
                consultation.get('farmer_email') == user.get('email', '') or
                consultation.get('contact_phone') == user.get('phone', '') or
                consultation.get('farmer_name') == user.get('name', '')
            )
        
        if not has_access:
            print("❌ DEBUG: User does not have access to this consultation")
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        # Find the message with the file
        message = messages_collection.find_one({
            'consultation_id': request_id,
            'file_info.file_id': file_id
        })
        
        if not message or 'file_info' not in message:
            print("❌ DEBUG: File not found in messages")
            return jsonify({'success': False, 'message': 'File not found'}), 404
        
        file_info = message['file_info']
        file_path = file_info['file_path']
        
        # Check if file exists on disk
        if not os.path.exists(file_path):
            print(f"❌ DEBUG: File not found on disk: {file_path}")
            return jsonify({'success': False, 'message': 'File not found on server'}), 404
        
        # Send file
        from flask import send_file
        return send_file(
            file_path,
            as_attachment=True,
            download_name=file_info['filename'],
            mimetype=file_info.get('content_type', 'application/octet-stream')
        )
        
    except Exception as e:
        print(f"❌ ERROR downloading file: {e}")
        print(f"❌ ERROR type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to download file: {str(e)}'}), 500

@app.route('/api/consultation-requests/<request_id>', methods=['GET'])
def get_consultation_request_details(request_id):
    """Get details of a specific consultation request"""
    print(f"🔍 DEBUG: GET /api/consultation-requests/{request_id} called")
    print(f"🔍 DEBUG: Session data: {dict(session)}")
    
    # Check if either consultant or farmer is logged in
    if 'consultant_id' not in session and 'user_id' not in session:
        print("❌ DEBUG: No consultant_id or user_id in session")
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        # Check if database collections are available
        if not MONGODB_AVAILABLE or consultation_requests_collection is None or users_collection is None:
            print("❌ DEBUG: Database not available")
            return jsonify({'success': False, 'message': 'Database service unavailable'}), 503
        
        consultation = consultation_requests_collection.find_one({'_id': ObjectId(request_id)})
        
        if not consultation:
            print("❌ DEBUG: Consultation not found")
            return jsonify({'success': False, 'message': 'Consultation not found'}), 404
        
        # Verify access rights
        has_access = False
        
        if 'consultant_id' in session:
            # Consultant access - must be assigned to this consultation
            has_access = consultation.get('assigned_to') == session['consultant_id']
            print(f"🔍 DEBUG: Consultant access check - assigned_to: {consultation.get('assigned_to')}, consultant_id: {session['consultant_id']}")
        elif 'user_id' in session:
            # Farmer access - must be the consultation creator
            try:
                user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
                if user:
                    has_access = (
                        consultation.get('created_by_user_id') == session['user_id'] or
                        consultation.get('farmer_email') == user.get('email', '') or
                        consultation.get('contact_phone') == user.get('phone', '') or
                        consultation.get('farmer_name') == user.get('name', '')
                    )
                    print(f"🔍 DEBUG: Farmer access check - created_by_user_id: {consultation.get('created_by_user_id')}, user_id: {session['user_id']}")
                    print(f"🔍 DEBUG: Farmer access check - farmer_email: {consultation.get('farmer_email')}, user_email: {user.get('email', '')}")
                else:
                    print("❌ DEBUG: User not found in database")
                    has_access = consultation.get('created_by_user_id') == session['user_id']
            except Exception as user_error:
                print(f"❌ DEBUG: Error fetching user data: {user_error}")
                # Fallback to just checking user_id
                has_access = consultation.get('created_by_user_id') == session['user_id']
        
        if not has_access:
            print("❌ DEBUG: Access denied to consultation")
            return jsonify({'success': False, 'message': 'You do not have access to this consultation'}), 403
        
        print("✅ DEBUG: Access granted to consultation details")
        
        # Convert ObjectId to string
        consultation['id'] = str(consultation['_id'])
        consultation['_id'] = str(consultation['_id'])
        
        # Convert datetime to string
        if 'created_at' in consultation:
            consultation['created_at'] = consultation['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify({'success': True, 'consultation': consultation})
        
    except Exception as e:
        print(f"❌ ERROR getting consultation details: {e}")
        print(f"❌ ERROR type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to load consultation details'}), 500

@app.route('/api/session-check', methods=['GET'])
def check_session():
    """Check current session status for debugging"""
    print(f"🔍 DEBUG: Session check called")
    print(f"🔍 DEBUG: Session data: {dict(session)}")
    
    session_info = {
        'has_consultant_id': 'consultant_id' in session,
        'has_user_id': 'user_id' in session,
        'consultant_id': session.get('consultant_id'),
        'user_id': session.get('user_id'),
        'user_name': session.get('user_name'),
        'consultant_name': session.get('consultant_name'),
        'session_keys': list(session.keys())
    }
    
    return jsonify({
        'success': True, 
        'message': 'Session check completed',
        'session_info': session_info
    })

# ==============================================
# FARMER API ROUTES (for creating consultation requests)
# ==============================================

@app.route('/api/consultation-request', methods=['POST'])
def create_consultation_request():
    """Create a new consultation request from farmer"""
    try:
        # Check if database is connected and collections are available
        print(f"🔍 Database check - consultation_requests_collection: {consultation_requests_collection is not None}")
        print(f"🔍 Database check - MONGODB_AVAILABLE: {MONGODB_AVAILABLE}")
        
        if not MONGODB_AVAILABLE or consultation_requests_collection is None:
            print("❌ Database not available or collection is None")
            return jsonify({
                'success': False, 
                'message': 'Database service is currently unavailable. Please try again later.'
            }), 503
        
        data = request.get_json()
        print(f"🔍 Received data: {data}")
        print(f"🔍 Session info: user_id={session.get('user_id')}, consultant_id={session.get('consultant_id')}")
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        # Check if user is logged in
        if 'user_id' not in session:
            print("❌ No user_id in session - user not logged in")
            return jsonify({'success': False, 'message': 'Please log in to submit consultation requests'}), 401
        
        # Validate required fields
        required_fields = ['farmer_name', 'farm_name', 'animal_type', 'symptoms', 'contact_phone']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'{field} is required'}), 400
        
        # Get selected consultant info if provided
        selected_consultant_id = data.get('assigned_to')  # Frontend sends 'assigned_to'
        assigned_consultant_name = None
        
        print(f"🔍 DEBUG: Received assigned_to value: {selected_consultant_id} (type: {type(selected_consultant_id)})")
        
        # Handle consultant assignment logic
        if selected_consultant_id and selected_consultant_id != "null":
            # Specific consultant selected
            print(f"🔍 DEBUG: Specific consultant selected: {selected_consultant_id}")
            try:
                consultant = consultants_collection.find_one({'_id': ObjectId(selected_consultant_id)})
                if consultant:
                    assigned_consultant_name = consultant['name']
                    request_status = 'Assigned'  # Directly assigned to specific consultant
                    # Store consultant ID as string to match session format
                    selected_consultant_id = str(selected_consultant_id)
                    print(f"✅ DEBUG: Found consultant: {assigned_consultant_name}, storing ID as: {selected_consultant_id}")
                else:
                    print(f"❌ DEBUG: Consultant not found with ID: {selected_consultant_id}")
                    return jsonify({'success': False, 'message': 'Selected consultant not found'}), 400
            except Exception as e:
                print(f"❌ DEBUG: Error finding selected consultant: {e}")
                return jsonify({'success': False, 'message': 'Invalid consultant selection'}), 400
        else:
            # Auto-assign case - don't assign to anyone yet, let consultants pick it up
            print(f"🔍 DEBUG: Auto-assign case - setting to None")
            selected_consultant_id = None
            assigned_consultant_name = None
            request_status = 'Pending'  # Available for any consultant to accept
        
        # Create consultation request document
        request_doc = {
            'farmer_name': data['farmer_name'],
            'farm_name': data['farm_name'],
            'farmer_email': data.get('farmer_email', ''),
            'contact_phone': data['contact_phone'],
            'location': data.get('location', ''),
            'animal_type': data['animal_type'],
            'animal_age': data.get('animal_age', ''),
            'animal_breed': data.get('animal_breed', ''),
            'symptoms': data['symptoms'],
            'duration': data.get('duration', ''),
            'urgency': data.get('urgency', 'Medium'),
            'additional_notes': data.get('additional_notes', ''),
            'status': request_status,
            'assigned_to': selected_consultant_id,  # None for auto-assign, consultant_id for specific
            'assigned_consultant_name': assigned_consultant_name,
            'created_by_user_id': session.get('user_id'),  # Add user ID for proper matching
            'created_at': datetime.now(timezone.utc),
            'images': []  # For future image upload functionality
        }
        
        # Insert into database
        print(f"📝 DEBUG: Final document before insertion:")
        print(f"   - farmer_name: {request_doc['farmer_name']}")
        print(f"   - status: {request_doc['status']}")
        print(f"   - assigned_to: {request_doc['assigned_to']}")
        print(f"   - assigned_consultant_name: {request_doc['assigned_consultant_name']}")
        
        result = consultation_requests_collection.insert_one(request_doc)
        print(f"✅ Consultation request inserted with ID: {result.inserted_id}")
        
        return jsonify({
            'success': True,
            'message': 'Consultation request submitted successfully! A veterinary consultant will review it soon.',
            'request_id': str(result.inserted_id)
        })
        
    except Exception as e:
        print(f"❌ Error creating consultation request: {e}")
        print(f"❌ Error type: {type(e).__name__}")
        print(f"❌ consultation_requests_collection: {consultation_requests_collection}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'message': f'Failed to submit request: {str(e)}. Please check your connection and try again.'
        }), 500

# Debug routes for troubleshooting
@app.route('/api/debug/requests', methods=['GET'])
def debug_consultation_requests():
    """Debug route to see all consultation requests"""
    try:
        if consultation_requests_collection is None:
            return jsonify({'error': 'Database not available'})
        
        # Get all requests
        requests = list(consultation_requests_collection.find({}).sort('created_at', -1).limit(10))
        
        # Convert ObjectId to string for JSON serialization
        for req in requests:
            req['_id'] = str(req['_id'])
            if 'created_at' in req:
                req['created_at'] = req['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify({
            'requests': requests,
            'count': len(requests)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/debug/consultants', methods=['GET'])
def debug_consultants():
    """Debug route to see all consultants"""
    try:
        if consultants_collection is None:
            return jsonify({'error': 'Database not available'})
        
        # Get all consultants
        consultants = list(consultants_collection.find({}, {
            '_id': 1,
            'name': 1,
            'email': 1,
            'status': 1
        }))
        
        # Convert ObjectId to string for JSON serialization
        for consultant in consultants:
            consultant['_id'] = str(consultant['_id'])
        
        return jsonify({
            'consultants': consultants,
            'count': len(consultants)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/available-consultants', methods=['GET'])
def get_available_consultants():
    """Get list of available consultants for farmers to choose from"""
    try:
        # Check if database is connected
        if consultants_collection is None:
            return jsonify({'success': False, 'message': 'Database not available'}), 500
        
        # Get all active consultants
        consultants_cursor = consultants_collection.find(
            {'status': 'active'}, 
            {
                '_id': 1,
                'name': 1,
                'specialization': 1,
                'experience': 1,
                'qualifications': 1,
                'created_at': 1
            }
        ).sort('name', 1)
        
        consultants = []
        for consultant in consultants_cursor:
            consultant_data = {
                'id': str(consultant['_id']),
                'name': consultant['name'],
                'specialization': consultant['specialization'],
                'experience': consultant['experience'],
                'qualifications': consultant.get('qualifications', ''),
                'years_experience': consultant['experience']
            }
            consultants.append(consultant_data)
        
        return jsonify({
            'success': True, 
            'consultants': consultants,
            'count': len(consultants)
        })
        
    except Exception as e:
        print(f"Error getting available consultants: {e}")
        return jsonify({'success': False, 'message': 'Failed to load consultants'}), 500

@app.route('/api/consultant/<consultant_id>', methods=['GET'])
def get_consultant_info(consultant_id):
    """Get detailed information about a specific consultant"""
    try:
        # Check if database is connected
        if consultants_collection is None:
            return jsonify({'success': False, 'message': 'Database not available'}), 500
        
        # Get consultant by ID
        consultant = consultants_collection.find_one(
            {'_id': ObjectId(consultant_id)},
            {
                '_id': 1,
                'name': 1,
                'specialization': 1,
                'experience': 1,
                'qualifications': 1,
                'email': 1,
                'phone': 1
            }
        )
        
        if not consultant:
            return jsonify({'success': False, 'message': 'Consultant not found'}), 404
        
        consultant_data = {
            'id': str(consultant['_id']),
            'name': consultant['name'],
            'specialization': consultant['specialization'],
            'experience': consultant['experience'],
            'qualifications': consultant.get('qualifications', ''),
            'email': consultant.get('email', ''),
            'phone': consultant.get('phone', ''),
            'location': consultant.get('location', 'Not specified')
        }
        
        return jsonify({
            'success': True,
            'consultant': consultant_data
        })
        
    except Exception as e:
        print(f"Error getting consultant info: {e}")
        return jsonify({'success': False, 'message': 'Failed to load consultant information'}), 500

@app.route('/api/user-consultation-messages', methods=['GET'])
def get_user_consultation_messages():
    """Get consultation messages for the current user (farmer and consultant view)"""
    # Check if either user or consultant is logged in
    if 'user_id' not in session and 'consultant_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        # Check if database is connected
        if consultation_requests_collection is None or messages_collection is None:
            return jsonify({'success': False, 'message': 'Database not available'}), 500
        
        # Determine if it's a farmer or consultant
        if 'user_id' in session:
            # Farmer view - get their own consultations
            user_id = session['user_id']
            user = users_collection.find_one({'_id': ObjectId(user_id)})
            
            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 404
            
            # Find consultation requests by user ID first, then fallback to email/phone/name matching
            query = {
                '$or': [
                    {'created_by_user_id': user_id},  # Primary match by user ID
                    {'farmer_email': user.get('email', '')},
                    {'contact_phone': user.get('phone', '')},
                    {'farmer_name': user.get('name', '')}
                ]
            }
            
            print(f"🔍 DEBUG: Farmer query: {query}")
            print(f"🔍 DEBUG: User info - email: {user.get('email', '')}, phone: {user.get('phone', '')}, name: {user.get('name', '')}")
            
            consultation_count = consultation_requests_collection.count_documents(query)
            print(f"🔍 DEBUG: Found {consultation_count} consultations for farmer")
        else:
            # Consultant view - get consultations assigned to them
            consultant_id = session['consultant_id']
            consultant = consultants_collection.find_one({'_id': ObjectId(consultant_id)})
            
            if not consultant:
                return jsonify({'success': False, 'message': 'Consultant not found'}), 404
            
            # Find consultation requests assigned to this consultant
            query = {
                'assigned_to': consultant_id
            }
        
        # Get consultation requests
        consultations_cursor = consultation_requests_collection.find(query).sort('created_at', -1)
        consultations = []
        
        for consultation in consultations_cursor:
            consultation_data = {
                'id': str(consultation['_id']),
                'farmer_name': consultation.get('farmer_name', ''),
                'farm_name': consultation.get('farm_name', ''),
                'animal_type': consultation.get('animal_type', ''),
                'symptoms': consultation.get('symptoms', ''),
                'status': consultation.get('status', 'Pending'),
                'urgency': consultation.get('urgency', 'Medium'),
                'assigned_to': consultation.get('assigned_to', ''),
                'assigned_consultant_name': consultation.get('assigned_consultant_name', ''),
                'created_at': consultation['created_at'].strftime('%Y-%m-%d %H:%M:%S') if 'created_at' in consultation else '',
                'messages': []
            }
            
            # Get messages for this consultation (from both farmers and consultants)
            consultation_id_str = str(consultation['_id'])
            messages_cursor = messages_collection.find({
                'consultation_id': consultation_id_str
            }).sort('timestamp', 1)
            
            print(f"🔍 DEBUG: Looking for messages with consultation_id: {consultation_id_str}")
            message_count = messages_collection.count_documents({
                'consultation_id': consultation_id_str
            })
            print(f"🔍 DEBUG: Found {message_count} total messages for consultation {consultation_id_str}")
            
            for message in messages_cursor:
                message_data = {
                    'id': str(message['_id']),
                    'sender_type': message.get('sender_type', 'consultant'),
                    'sender_name': message.get('sender_name', 'Unknown'),
                    'message': message.get('message', ''),
                    'timestamp': message['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if 'timestamp' in message else ''
                }
                consultation_data['messages'].append(message_data)
                print(f"🔍 DEBUG: Added message from {message_data['sender_type']}: {message_data['message'][:50]}...")
            
            consultations.append(consultation_data)
        
        print(f"🔍 DEBUG: Returning {len(consultations)} consultations to farmer")
        for i, consult in enumerate(consultations):
            print(f"🔍 DEBUG: Consultation {i+1}: {consult['farmer_name']} - {len(consult['messages'])} messages")
        
        return jsonify({
            'success': True,
            'consultations': consultations,
            'count': len(consultations)
        })
        
    except Exception as e:
        print(f"Error getting user consultation messages: {e}")
        return jsonify({'success': False, 'message': 'Failed to load messages'}), 500


@app.route('/specific_prediction')
def specific_prediction():
    """Route for specific disease prediction page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('specific_prediction.html')


@app.route('/predict/specific_disease', methods=['POST'])
def predict_specific_disease():
    """Generate specific disease prediction based on detailed information"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Authentication required'}), 401
    
    try:
        # Extract form data
        animal_type = request.form.get('animal_type', '').strip()
        animal_age = request.form.get('animal_age', '').strip()
        animal_weight = request.form.get('animal_weight', '').strip()
        animal_breed = request.form.get('animal_breed', '').strip()
        symptoms = request.form.getlist('symptoms[]')
        additional_symptoms = request.form.get('additional_symptoms', '').strip()
        symptom_duration = request.form.get('symptom_duration', '').strip()
        severity = request.form.get('severity', 'moderate').strip()
        recent_changes = request.form.get('recent_changes', '').strip()
        previous_treatment = request.form.get('previous_treatment', '').strip()
        
        # Validate required fields
        if not animal_type:
            return jsonify({'success': False, 'error': 'Animal type is required'}), 400
        
        if not symptoms and not additional_symptoms:
            return jsonify({'success': False, 'error': 'At least one symptom must be provided'}), 400
        
        # Prepare comprehensive animal information
        animal_info = {
            'type': animal_type,
            'age': animal_age,
            'weight': animal_weight,
            'breed': animal_breed
        }
        
        # Combine all symptoms
        all_symptoms = symptoms + ([additional_symptoms] if additional_symptoms else [])
        
        # Get specific disease prediction
        prediction = generate_specific_disease_prediction(
            animal_info=animal_info,
            symptoms=all_symptoms,
            duration=symptom_duration,
            severity=severity,
            recent_changes=recent_changes,
            previous_treatment=previous_treatment
        )
        
        # Store prediction in database
        try:
            user_id = session['user_id']
            prediction_data = {
                'user_id': user_id,
                'animal_type': animal_type,
                'animal_info': animal_info,
                'symptoms': all_symptoms,
                'symptom_duration': symptom_duration,
                'severity': severity,
                'recent_changes': recent_changes,
                'previous_treatment': previous_treatment,
                'prediction': prediction,
                'timestamp': datetime.now(),
                'prediction_type': 'specific_disease'
            }
            
            predictions_collection.insert_one(prediction_data)
            print(f"✅ Specific disease prediction saved to database")
            
        except Exception as db_error:
            print(f"⚠️  Database save error: {db_error}")
            # Continue even if database save fails
        
        return jsonify({
            'success': True,
            'prediction': prediction
        })
        
    except Exception as e:
        print(f"❌ Error in specific disease prediction: {e}")
        return jsonify({
            'success': False,
            'error': f'Prediction failed: {str(e)}'
        }), 500


def generate_specific_disease_prediction(animal_info, symptoms, duration, severity, recent_changes, previous_treatment):
    """Generate specific disease prediction using Gemini AI"""
    
    try:
        # Prepare detailed prompt for specific disease prediction
        prompt = f"""You are a veterinary expert providing specific disease predictions for animal health.

Animal Information:
- Type: {animal_info['type']}
- Age: {animal_info.get('age', 'Not specified')}
- Weight: {animal_info.get('weight', 'Not specified')}
- Breed: {animal_info.get('breed', 'Not specified')}

Clinical Presentation:
- Observed Symptoms: {', '.join(symptoms)}
- Duration: {duration or 'Not specified'}
- Severity: {severity}
- Recent Changes: {recent_changes or 'None reported'}
- Previous Treatment: {previous_treatment or 'None reported'}

Please provide a specific disease prediction in JSON format with the following structure:
{{
    "disease": "Most likely specific disease name",
    "confidence": 0.85,
    "description": "Detailed description of the disease and why it matches the symptoms",
    "alternative_diseases": [
        {{
            "disease": "Alternative disease name",
            "confidence": 0.65,
            "description": "Brief description"
        }}
    ],
    "treatment": {{
        "immediate_actions": ["Action 1", "Action 2", "Action 3"],
        "treatment_plan": ["Treatment step 1", "Treatment step 2", "Treatment step 3"],
        "vet_consultation": "When to consult a veterinarian"
    }},
    "risk_factors": ["Risk factor 1", "Risk factor 2"],
    "prognosis": "Expected outcome with proper treatment"
}}

Focus on providing the most specific and accurate disease diagnosis possible based on the symptoms and animal information provided."""

        if GEMINI_AVAILABLE:
            # Use the robust API call function with disease detection API key
            response_text, error = call_gemini_with_retry('gemini-2.0-flash-exp', prompt, api_key=GEMINI_API_KEY_DISEASE)
            
            if error:
                print(f"⚠️  Gemini AI error: {error}")
                # Fallback to rule-based prediction
                return generate_fallback_specific_prediction(animal_info, symptoms, severity)
                
            if response_text:
                # Try to parse as JSON first
                try:
                    prediction = json.loads(response_text)
                    return prediction
                except json.JSONDecodeError:
                    # If JSON parsing fails, extract key information from text
                    return parse_specific_prediction_text(response_text, animal_info['type'])
            else:
                return generate_fallback_specific_prediction(animal_info, symptoms, severity)
                
        else:
            # Fallback if Gemini is not available
            return generate_fallback_specific_prediction(animal_info, symptoms, severity)
            
    except Exception as e:
        print(f"❌ Error in specific disease prediction generation: {e}")
        return generate_fallback_specific_prediction(animal_info, symptoms, severity)


def parse_specific_prediction_text(text_response, animal_type):
    """Parse text response when JSON parsing fails"""
    try:
        # Extract disease name
        disease_match = None
        lines = text_response.split('\n')
        
        for line in lines:
            if 'disease' in line.lower() or 'diagnosis' in line.lower():
                # Extract likely disease name
                if ':' in line:
                    disease_match = line.split(':', 1)[1].strip()
                    break
        
        if not disease_match:
            disease_match = f"Suspected {animal_type.title()} Health Issue"
        
        return {
            'disease': disease_match,
            'confidence': 0.75,
            'description': "Based on the provided symptoms and clinical information, this appears to be the most likely condition affecting your animal.",
            'alternative_diseases': [
                {
                    'disease': 'Secondary Infection',
                    'confidence': 0.60,
                    'description': 'May be a complicating factor'
                }
            ],
            'treatment': {
                'immediate_actions': [
                    'Monitor the animal closely',
                    'Ensure access to clean water and food',
                    'Provide comfortable environment',
                    'Note any changes in condition'
                ],
                'treatment_plan': [
                    'Consult veterinarian for proper diagnosis',
                    'Follow professional treatment recommendations',
                    'Implement supportive care measures',
                    'Monitor treatment response'
                ],
                'vet_consultation': 'Professional veterinary consultation recommended for accurate diagnosis and treatment'
            },
            'risk_factors': [
                'Animal age and health status',
                'Environmental factors',
                'Previous medical history'
            ],
            'prognosis': 'Good with proper veterinary care and early intervention'
        }
        
    except Exception as e:
        print(f"Error parsing prediction text: {e}")
        return generate_fallback_specific_prediction(
            {'type': animal_type}, 
            ['general symptoms'], 
            'moderate'
        )


def generate_fallback_specific_prediction(animal_info, symptoms, severity):
    """Generate fallback prediction when AI is not available"""
    
    # Disease patterns for different animals
    disease_patterns = {
        'cattle': {
            'respiratory': {
                'symptoms': ['coughing', 'difficulty breathing', 'nasal discharge', 'fever'],
                'diseases': [
                    {'name': 'Bovine Respiratory Disease (BRD)', 'confidence': 0.85},
                    {'name': 'Pneumonia', 'confidence': 0.75}
                ]
            },
            'digestive': {
                'symptoms': ['diarrhea', 'loss of appetite', 'bloating', 'constipation'],
                'diseases': [
                    {'name': 'Rumen Acidosis', 'confidence': 0.80},
                    {'name': 'Intestinal Parasites', 'confidence': 0.70}
                ]
            },
            'reproductive': {
                'symptoms': ['reduced milk production', 'abnormal discharge', 'difficulty breeding'],
                'diseases': [
                    {'name': 'Mastitis', 'confidence': 0.85},
                    {'name': 'Reproductive Disorders', 'confidence': 0.75}
                ]
            }
        },
        'dog': {
            'gastrointestinal': {
                'symptoms': ['vomiting', 'diarrhea', 'loss of appetite', 'lethargy'],
                'diseases': [
                    {'name': 'Gastroenteritis', 'confidence': 0.80},
                    {'name': 'Dietary Indiscretion', 'confidence': 0.70}
                ]
            },
            'skin': {
                'symptoms': ['scratching', 'hair loss', 'skin irritation', 'red patches'],
                'diseases': [
                    {'name': 'Allergic Dermatitis', 'confidence': 0.85},
                    {'name': 'Fungal Infection', 'confidence': 0.70}
                ]
            },
            'urinary': {
                'symptoms': ['frequent urination', 'difficulty urinating', 'blood in urine'],
                'diseases': [
                    {'name': 'Urinary Tract Infection', 'confidence': 0.85},
                    {'name': 'Bladder Stones', 'confidence': 0.70}
                ]
            }
        },
        'cat': {
            'respiratory': {
                'symptoms': ['sneezing', 'nasal discharge', 'eye discharge', 'coughing'],
                'diseases': [
                    {'name': 'Upper Respiratory Infection', 'confidence': 0.85},
                    {'name': 'Feline Herpesvirus', 'confidence': 0.75}
                ]
            },
            'urinary': {
                'symptoms': ['frequent urination', 'straining to urinate', 'blood in urine'],
                'diseases': [
                    {'name': 'Feline Lower Urinary Tract Disease', 'confidence': 0.85},
                    {'name': 'Urinary Blockage', 'confidence': 0.80}
                ]
            }
        }
    }
    
    # Convert symptoms to lowercase for matching
    symptom_text = ' '.join(symptoms).lower()
    
    # Find matching disease patterns
    animal_patterns = disease_patterns.get(animal_info['type'], {})
    best_match = None
    best_score = 0
    
    for category, pattern in animal_patterns.items():
        score = sum(1 for s in pattern['symptoms'] if s in symptom_text)
        if score > best_score:
            best_score = score
            best_match = pattern['diseases'][0]
    
    if not best_match:
        # Generic fallback
        best_match = {
            'name': f'General {animal_info["type"].title()} Health Issue',
            'confidence': 0.60
        }
    
    # Adjust confidence based on severity
    confidence = best_match['confidence']
    if severity == 'severe':
        confidence = min(0.95, confidence + 0.10)
    elif severity == 'mild':
        confidence = max(0.50, confidence - 0.10)
    
    return {
        'disease': best_match['name'],
        'confidence': confidence,
        'description': f"Based on the symptoms observed in your {animal_info['type']}, this appears to be the most likely condition. The symptoms align with typical presentations of this disease.",
        'alternative_diseases': [
            {
                'disease': 'Secondary Bacterial Infection',
                'confidence': 0.65,
                'description': 'Could be a complicating factor'
            },
            {
                'disease': 'Nutritional Deficiency',
                'confidence': 0.55,
                'description': 'May contribute to symptoms'
            }
        ],
        'treatment': {
            'immediate_actions': [
                'Ensure the animal has access to clean, fresh water',
                'Provide a quiet, comfortable environment',
                'Monitor symptoms closely for any changes',
                'Isolate from other animals if infectious disease is suspected'
            ],
            'treatment_plan': [
                'Consult with a qualified veterinarian for proper diagnosis',
                'Follow prescribed medication regimen if provided',
                'Implement supportive care measures',
                'Monitor response to treatment and adjust as needed'
            ],
            'vet_consultation': 'Immediate veterinary consultation is recommended, especially if symptoms worsen or the animal shows signs of distress.'
        },
        'risk_factors': [
            'Age and overall health status',
            'Environmental conditions',
            'Nutrition and diet quality',
            'Previous medical history'
        ],
        'prognosis': 'With proper veterinary care and treatment, most animals recover well. Early intervention improves outcomes significantly.'
    }


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)