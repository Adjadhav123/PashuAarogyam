import os
import logging
import traceback
import json
import time
import random
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try imports with graceful fallbacks
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
    logger.info("✅ Google Generative AI imported successfully")
except ImportError as e:
    logger.error(f"❌ Google Generative AI not available: {e}")
    GENAI_AVAILABLE = False

try:
    import PyPDF2
    PDF_AVAILABLE = True
    logger.info("✅ PyPDF2 imported successfully")
except ImportError as e:
    logger.error(f"❌ PyPDF2 not available: {e}")
    PDF_AVAILABLE = False

try:
    from PIL import Image
    import io
    import base64
    IMAGE_PROCESSING_AVAILABLE = True
    logger.info("✅ Image processing libraries imported successfully")
except ImportError as e:
    logger.error(f"❌ Image processing not available: {e}")
    IMAGE_PROCESSING_AVAILABLE = False

try:
    from deep_translator import GoogleTranslator
    TRANSLATION_AVAILABLE = True
    logger.info("✅ Translation library imported successfully")
except ImportError as e:
    logger.error(f"❌ Translation not available: {e}")
    TRANSLATION_AVAILABLE = False

# Rate limiting for Gemini API - Relaxed for dedicated chatbot API
class GeminiRateLimiter:
    def __init__(self):
        self.last_call_time = 0
        self.min_interval = 0.3  # Reduced for chatbot with dedicated API
        self.rate_limit_until = 0  # Timestamp until when we're rate limited
        self.consecutive_failures = 0
        
    def wait_if_needed(self):
        """Wait if we need to respect rate limits"""
        current_time = time.time()
        
        # Check if we're still in rate limit period
        if current_time < self.rate_limit_until:
            wait_time = self.rate_limit_until - current_time
            logger.info(f"⏳ Rate limited. Waiting {wait_time:.1f} seconds...")
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
        """Handle 429 rate limit error - Reduced wait time for chatbot"""
        self.consecutive_failures += 1
        base_wait = min(20, 1.3 ** self.consecutive_failures)  # Even more reduced
        jitter = random.uniform(0.9, 1.1)  # Minimal jitter
        wait_time = base_wait * jitter
        
        self.rate_limit_until = time.time() + wait_time
        self.min_interval = min(2, self.min_interval * 1.1)  # Minimal increase
        
        logger.warning(f"⚠️ Rate limit hit. Backing off for {wait_time:.1f} seconds...")
        return wait_time
        
    def reset_on_success(self):
        """Reset failure count on successful call"""
        self.consecutive_failures = 0
        self.min_interval = max(0.3, self.min_interval * 0.97)  # Gradually reduce interval

class AnimalDiseaseChatbot:
    def __init__(self, api_key):
        """Initialize the chatbot with comprehensive error handling"""
        try:
            logger.info("🔄 Initializing Animal Disease Chatbot...")
            self.api_key = api_key
            self.model = None
            self.vision_model = None
            self.conversation_history = []
            self.session_histories = {}  # Store multiple session histories
            self.current_session_key = None
            self.rate_limiter = GeminiRateLimiter()  # Add rate limiter
            
            # Initialize services step by step
            gemini_success = self._initialize_genai()
            
            if not gemini_success:
                logger.warning("⚠️  Gemini AI initialization failed, but chatbot will continue with limited functionality")
            
            logger.info("✅ Animal Disease Chatbot initialized successfully!")
            
        except Exception as e:
            logger.error(f"❌ Critical error initializing chatbot: {e}")
            logger.error(traceback.format_exc())
            # Don't raise exception, allow degraded functionality
    
    def _call_gemini_with_retry(self, model, prompt, image=None, max_retries=2):
        """
        Call Gemini API with proper error handling, rate limiting, and retries
        Reduced retries since we have dedicated chatbot API key
        """
        if not GENAI_AVAILABLE or not model:
            return None, "Gemini AI is not available"
            
        for attempt in range(max_retries):
            try:
                # Wait if rate limited
                was_rate_limited = self.rate_limiter.wait_if_needed()
                
                # Make request
                if image:
                    response = model.generate_content([prompt, image])
                else:
                    response = model.generate_content(prompt)
                
                if response and response.text:
                    self.rate_limiter.reset_on_success()
                    return response.text.strip(), None
                else:
                    return None, "Empty response from Gemini AI"
                    
            except Exception as e:
                error_str = str(e).lower()
                
                # Handle different types of errors
                if "429" in error_str or "resource exhausted" in error_str or "quota" in error_str:
                    wait_time = self.rate_limiter.handle_rate_limit_error()
                    
                    if attempt < max_retries - 1:
                        logger.info(f"🔄 Retrying after rate limit (attempt {attempt + 1}/{max_retries})...")
                        time.sleep(wait_time)
                        continue
                    else:
                        return None, f"Rate limit exceeded after {max_retries} attempts. Please try again later."
                        
                elif "network" in error_str or "connection" in error_str or "timeout" in error_str:
                    if attempt < max_retries - 1:
                        wait_time = (attempt + 1) * 2  # Linear backoff for network issues
                        logger.info(f"🌐 Network error, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})...")
                        time.sleep(wait_time)
                        continue
                    else:
                        return None, f"Network error after {max_retries} attempts. Please check your connection."
                        
                elif "invalid" in error_str or "permission" in error_str:
                    return None, f"API error: {str(e)}"
                    
                else:
                    if attempt < max_retries - 1:
                        wait_time = (attempt + 1) * 1.5
                        logger.info(f"⚠️ Gemini error, retrying in {wait_time}s: {str(e)[:100]}...")
                        time.sleep(wait_time)
                        continue
                    else:
                        return None, f"Gemini API error: {str(e)}"
        
        return None, "Failed after all retry attempts"
    
    def _initialize_genai(self):
        """Initialize Google Generative AI"""
        try:
            if not GENAI_AVAILABLE:
                logger.warning("⚠️  Google Generative AI not available")
                return False
                
            if not self.api_key or self.api_key.strip() == "":
                logger.error("❌ API key is empty or not provided")
                return False
                
            # Configure the API key
            genai.configure(api_key=self.api_key)
            logger.info("✅ Gemini AI configured with API key")
            
            # Try to initialize text model with newer model
            try:
                self.model = genai.GenerativeModel('gemini-2.0-flash-exp')
                logger.info("✅ Text model initialized successfully with gemini-2.0-flash-exp")
            except Exception as e:
                logger.error(f"❌ Failed to initialize gemini-2.0-flash-exp: {e}")
                try:
                    # Fallback to older model if available
                    self.model = genai.GenerativeModel('gemini-1.5-flash')
                    logger.info("✅ Text model initialized with gemini-1.5-flash fallback")
                except Exception as e2:
                    logger.error(f"❌ Failed to initialize fallback model: {e2}")
                    try:
                        # Last resort - try the basic model
                        self.model = genai.GenerativeModel('gemini-pro')
                        logger.info("✅ Text model initialized with gemini-pro (legacy)")
                    except Exception as e3:
                        logger.error(f"❌ All text model initialization failed: {e3}")
                        return False
            
            # Try to initialize vision model with newer model
            try:
                self.vision_model = genai.GenerativeModel('gemini-2.0-flash-exp')
                logger.info("✅ Vision model initialized successfully with gemini-2.0-flash-exp")
            except Exception as e:
                logger.warning(f"⚠️  Vision model initialization failed: {e}")
                try:
                    # Fallback to older vision model
                    self.vision_model = genai.GenerativeModel('gemini-1.5-flash')
                    logger.info("✅ Vision model initialized with gemini-1.5-flash fallback")
                except Exception as e2:
                    logger.warning(f"⚠️  Vision model fallback failed: {e2}")
                    self.vision_model = None
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to configure Generative AI: {e}")
            return False
    
    def test_model_health(self):
        """Test if the model is working properly"""
        try:
            if not self.model:
                return False, "Model not initialized"
                
            # Simple test query
            test_response = self.model.generate_content("Test")
            if test_response and test_response.text:
                logger.info("✅ Model health check passed")
                return True, "Model is healthy"
            else:
                logger.warning("⚠️  Model health check failed - no response")
                return False, "Model not responding"
                
        except Exception as e:
            logger.error(f"❌ Model health check failed: {e}")
            return False, f"Model health check error: {str(e)}"
    
    def process_text_query(self, user_input, language='en', session_key=None):
        """Process text-based queries about animal diseases with session context"""
        try:
            # Validate input
            if not user_input or not user_input.strip():
                return {
                    'success': False,
                    'error': 'Empty input provided',
                    'type': 'text'
                }
            
            # Set current session key
            if session_key:
                self.current_session_key = session_key
                # Load session history if exists
                if session_key in self.session_histories:
                    self.conversation_history = self.session_histories[session_key]
                else:
                    self.conversation_history = []
                    self.session_histories[session_key] = self.conversation_history
            
            # Check if model is available
            if not self.model:
                logger.error("❌ AI model not available - check API key and network connection")
                return {
                    'success': False,
                    'error': 'AI model temporarily unavailable - please try again in a few moments',
                    'fallback_response': self._get_fallback_response(user_input),
                    'type': 'text'
                }
            
            # Only translate if absolutely necessary (not English and translation available)
            should_translate = language != 'en' and TRANSLATION_AVAILABLE
            
            # Use original input for English or if translation unavailable
            query_text = user_input
            if should_translate:
                try:
                    query_text = self._translate_text(user_input, language, 'en')
                except Exception as trans_error:
                    logger.warning(f"Translation failed, using original text: {trans_error}")
                    query_text = user_input
                    should_translate = False  # Don't translate response either
            
            # Build context from conversation history
            context = ""
            if self.conversation_history:
                # Include last few exchanges for context
                recent_history = self.conversation_history[-6:]  # Last 3 exchanges (6 messages)
                context_parts = []
                for hist in recent_history:
                    if 'user' in hist and 'assistant' in hist:
                        context_parts.append(f"User: {hist['user']}")
                        context_parts.append(f"Assistant: {hist['assistant']}")
                
                if context_parts:
                    context = "\nPrevious conversation:\n" + "\n".join(context_parts) + "\n\nCurrent question:\n"
            
            # Create context-aware veterinary prompt
            veterinary_prompt = f"""You are a veterinary AI assistant. {context}Answer this question: {query_text}

Provide:
- Accurate, practical advice
- Key symptoms or treatments  
- When to see a vet
- Prevention tips if relevant

Keep response focused and helpful."""
            
            try:
                logger.info("🤖 Generating text response...")
                
                # Use the robust API call function
                response_text, error = self._call_gemini_with_retry(self.model, veterinary_prompt)
                
                if error:
                    logger.error(f"❌ Text generation failed: {error}")
                    return {
                        'success': False,
                        'error': error,
                        'fallback_response': self._get_fallback_response(user_input),
                        'type': 'text'
                    }
                
                if response_text:
                    # Store in conversation history
                    try:
                        conversation_entry = {
                            'user': user_input,
                            'assistant': response_text,
                            'timestamp': datetime.now().isoformat(),
                            'language': language
                        }
                        self.conversation_history.append(conversation_entry)
                        
                        # Update session history
                        if self.current_session_key:
                            self.session_histories[self.current_session_key] = self.conversation_history
                            
                        # Keep only last 20 exchanges to prevent memory issues
                        if len(self.conversation_history) > 20:
                            self.conversation_history = self.conversation_history[-20:]
                            if self.current_session_key:
                                self.session_histories[self.current_session_key] = self.conversation_history
                    except:
                        pass  # Don't fail if history storage fails
                    
                    # Translate back to original language only if we translated the input
                    final_response = response_text
                    if should_translate:
                        try:
                            # For long responses in regional languages, provide a shorter summary
                            if len(response_text) > 2000 and language in ['mr', 'hi', 'ta', 'te', 'gu', 'kn', 'ml', 'pa', 'bn']:
                                # Create a shorter summary for translation
                                summary_prompt = f"Summarize this veterinary advice in 2-3 concise sentences: {response_text[:1000]}"
                                try:
                                    summary_text, summary_error = self._call_gemini_with_retry(self.model, summary_prompt)
                                    if summary_text and not summary_error:
                                        final_response = self._translate_text(summary_text, 'en', language)
                                        logger.info(f"✅ Provided translated summary for {language}")
                                    else:
                                        final_response = self._translate_text(response_text, 'en', language)
                                except Exception as summary_error:
                                    logger.warning(f"Summary generation failed, trying full translation: {summary_error}")
                                    final_response = self._translate_text(response_text, 'en', language)
                            else:
                                final_response = self._translate_text(response_text, 'en', language)
                        except Exception as trans_error:
                            logger.warning(f"Response translation failed, using English: {trans_error}")
                            final_response = response_text
                    
                    logger.info("✅ Text response generated successfully")
                    return {
                        'success': True,
                        'response': final_response,
                        'type': 'text',
                        'session_key': self.current_session_key
                    }
                else:
                    return {
                        'success': False,
                        'error': 'No response generated',
                        'fallback_response': self._get_fallback_response(user_input),
                        'type': 'text'
                    }
                    
            except Exception as generation_error:
                logger.error(f"❌ Text generation failed: {generation_error}")
                return {
                    'success': False,
                    'error': f'Generation failed: {str(generation_error)}',
                    'fallback_response': self._get_fallback_response(user_input),
                    'type': 'text'
                }
        
        except Exception as e:
            logger.error(f"❌ Error processing text query: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                'success': False,
                'error': str(e),
                'fallback_response': self._get_fallback_response(user_input),
                'type': 'text'
            }
    
    def analyze_image(self, image_data, question=None, language='en'):
        """Analyze uploaded images for disease detection"""
        try:
            # Check if vision model is available
            if not self.vision_model:
                logger.warning("⚠️ Vision model not available")
                return {
                    'success': False,
                    'error': 'Image analysis not available - vision model not initialized',
                    'fallback_response': 'Image analysis is currently unavailable. Please describe the symptoms in text instead.',
                    'type': 'image_analysis'
                }
            
            # Convert and validate image data
            try:
                if hasattr(image_data, 'read'):
                    # Flask FileStorage object
                    logger.info("📁 Processing file upload...")
                    image_bytes = image_data.read()
                    image_data.seek(0)  # Reset file pointer
                    
                    # Validate file size (max 10MB)
                    if len(image_bytes) > 10 * 1024 * 1024:
                        return {
                            'success': False,
                            'error': 'File too large. Please use images under 10MB.',
                            'type': 'image_analysis'
                        }
                        
                elif isinstance(image_data, str):
                    # Base64 encoded image
                    logger.info("🔗 Processing base64 image...")
                    image_bytes = base64.b64decode(image_data)
                else:
                    # Assume bytes
                    image_bytes = image_data
                
                # Validate image format
                try:
                    image = Image.open(io.BytesIO(image_bytes))
                    # Convert to RGB if needed
                    if image.mode not in ['RGB', 'RGBA']:
                        image = image.convert('RGB')
                    
                    # Resize if too large (max 2048x2048)
                    if image.width > 2048 or image.height > 2048:
                        image.thumbnail((2048, 2048), Image.Resampling.LANCZOS)
                    
                    logger.info(f"✅ Image processed: {image.width}x{image.height}, mode: {image.mode}")
                    
                except Exception as img_process_error:
                    logger.error(f"❌ Image format validation failed: {img_process_error}")
                    return {
                        'success': False,
                        'error': 'Invalid image format. Please use JPG, PNG, or WEBP images.',
                        'type': 'image_analysis'
                    }
                
            except Exception as img_error:
                logger.error(f"❌ Image processing failed: {img_error}")
                return {
                    'success': False,
                    'error': 'Failed to process uploaded image. Please try with a different image.',
                    'type': 'image_analysis'
                }
            
            # Default question if none provided
            if not question or not question.strip():
                question = "What do you see in this image? Are there any signs of disease or health issues?"
            
            # Translate question to English if needed (but only if really necessary)
            translated_question = question
            if language != 'en' and TRANSLATION_AVAILABLE:
                try:
                    translated_question = self._translate_text(question, language, 'en')
                except:
                    # If translation fails, use original question
                    translated_question = question
            
            # Create concise veterinary image analysis prompt
            image_prompt = f"""Analyze this animal image and answer: {translated_question}

Provide:
1. Animal type and visible condition
2. Any health concerns or disease signs
3. Recommendations
4. When to see a vet

Be specific but concise."""
            
            try:
                logger.info("🤖 Generating image analysis...")
                
                # Use the robust API call function
                response_text, error = self._call_gemini_with_retry(self.vision_model, image_prompt, image)
                
                if error:
                    logger.error(f"❌ Vision analysis failed: {error}")
                    return {
                        'success': False,
                        'error': error,
                        'fallback_response': 'Unable to analyze the image. Please describe what you see in text.',
                        'type': 'image_analysis'
                    }
                
                if response_text:
                    # Translate back to original language only if needed
                    final_response = response_text
                    if language != 'en' and TRANSLATION_AVAILABLE:
                        try:
                            final_response = self._translate_text(response_text, 'en', language)
                        except:
                            # If translation fails, use English response
                            final_response = response_text
                    
                    logger.info("✅ Image analysis completed successfully")
                    return {
                        'success': True,
                        'response': final_response,
                        'type': 'image_analysis'
                    }
                else:
                    logger.error("❌ No response from vision model")
                    return {
                        'success': False,
                        'error': 'No analysis generated',
                        'fallback_response': 'Unable to analyze the image. Please try again or describe the symptoms in text.',
                        'type': 'image_analysis'
                    }
                    
            except Exception as vision_error:
                logger.error(f"❌ Vision analysis failed: {vision_error}")
                return {
                    'success': False,
                    'error': f'Vision analysis error: {str(vision_error)}',
                    'fallback_response': 'Image analysis encountered an error. Please try again or describe the symptoms in text.',
                    'type': 'image_analysis'
                }
                return {
                    'success': False,
                    'error': f'Vision analysis failed: {str(vision_error)}',
                    'fallback_response': 'Image analysis failed. Please describe the symptoms in text instead.',
                    'type': 'image_analysis'
                }
        
        except Exception as e:
            logger.error(f"❌ Error analyzing image: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                'success': False,
                'error': str(e),
                'type': 'image_analysis'
            }
    
    def process_pdf(self, pdf_data, question=None, language='en'):
        """Process PDF documents and answer questions about them"""
        try:
            # Check if PDF processing is available
            if not PDF_AVAILABLE:
                return {
                    'success': False,
                    'error': 'PDF processing not available',
                    'fallback_response': 'PDF processing is currently unavailable. Please copy the text and paste it instead.',
                    'type': 'pdf_analysis'
                }
            
            # Extract text from PDF
            try:
                if hasattr(pdf_data, 'read'):
                    # Flask FileStorage object
                    pdf_bytes = pdf_data.read()
                    pdf_data.seek(0)  # Reset file pointer
                else:
                    pdf_bytes = pdf_data
                
                pdf_reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
                text_content = ""
                
                for page in pdf_reader.pages:
                    text_content += page.extract_text() + "\n"
                
                if not text_content.strip():
                    return {
                        'success': False,
                        'error': 'No text found in PDF',
                        'type': 'pdf_analysis'
                    }
                
            except Exception as pdf_error:
                logger.error(f"❌ PDF extraction failed: {pdf_error}")
                return {
                    'success': False,
                    'error': 'Failed to extract text from PDF',
                    'type': 'pdf_analysis'
                }
            
            # Default question if none provided
            if not question:
                question = "Summarize the key information in this document related to animal health and diseases."
            
            # Translate question to English if needed
            translated_question = self._translate_text(question, language, 'en')
            
            # Create combined query
            combined_query = f"""Based on the following document content, please answer: {translated_question}

Document content:
{text_content[:4000]}  # Limit content to avoid token limits

Please provide a comprehensive answer based on the document content."""
            
            # Process as text query
            return self.process_text_query(combined_query, language)
        
        except Exception as e:
            logger.error(f"❌ Error processing PDF: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                'success': False,
                'error': str(e),
                'type': 'pdf_analysis'
            }
    
    def _translate_text(self, text, source_lang, target_lang):
        """Translate text between languages - optimized for speed"""
        try:
            # Quick checks to avoid unnecessary translation
            if source_lang == target_lang:
                return text
            
            if not TRANSLATION_AVAILABLE:
                return text
            
            if not text or not text.strip() or len(text.strip()) < 3:
                return text
            
            # For Indian languages like Marathi, allow longer text translation
            max_length = 2000 if target_lang in ['mr', 'hi', 'ta', 'te', 'gu', 'kn', 'ml', 'pa', 'bn'] else 1000
            
            # Skip translation for very long texts to save time
            if len(text) > max_length:
                logger.info(f"⚡ Skipping translation for long text ({len(text)} chars > {max_length}) to improve speed")
                return text
            
            # Create translator and translate with timeout
            import threading
            import time
            
            result = {'translated': None, 'error': None}
            
            def translate_with_timeout():
                try:
                    translator = GoogleTranslator(source=source_lang, target=target_lang)
                    result['translated'] = translator.translate(text)
                except Exception as e:
                    result['error'] = str(e)
            
            # Run translation with 5 second timeout
            translation_thread = threading.Thread(target=translate_with_timeout)
            translation_thread.daemon = True
            translation_thread.start()
            translation_thread.join(timeout=5)
            
            if translation_thread.is_alive():
                logger.warning("⚡ Translation timed out, using original text")
                return text
            
            if result['error']:
                logger.warning(f"⚠️ Translation failed ({source_lang} → {target_lang}): {result['error']}")
                return text
            
            if result['translated']:
                logger.info(f"✅ Translation completed: {source_lang} → {target_lang}")
                return result['translated']
            else:
                return text
            
        except Exception as e:
            logger.warning(f"⚠️ Translation error ({source_lang} → {target_lang}): {e}")
            return text  # Return original text if translation fails
    
    def _get_fallback_response(self, user_input):
        """Provide helpful fallback response when AI is unavailable"""
        
        # Check for common animal health keywords
        keywords_responses = {
            'fever': '🌡️ For animal fever: Monitor temperature, ensure hydration, isolate if contagious, contact veterinarian if severe.',
            'diarrhea': '💧 For animal diarrhea: Ensure hydration, withhold food briefly, provide electrolytes, seek vet help if persistent.',
            'cough': '😷 For animal cough: Check for respiratory distress, isolate animal, ensure good ventilation, consult veterinarian.',
            'lameness': '🦵 For animal lameness: Rest the animal, check for injuries/swelling, limit movement, veterinary examination needed.',
            'mastitis': '🥛 For mastitis: Milk frequently, apply warm compresses, antibiotic treatment may be needed, consult veterinarian.',
            'vaccination': '💉 For vaccinations: Follow local vaccination schedule, maintain cold chain, record dates, consult veterinarian.',
        }
        
        user_lower = user_input.lower()
        for keyword, response in keywords_responses.items():
            if keyword in user_lower:
                return response
        
        # Default fallback response
        return """🩺 **Animal Health Guidance** 

I'm currently unable to provide AI-powered responses, but here's some general guidance:

**Emergency Signs - Contact Veterinarian Immediately:**
- Difficulty breathing, severe bleeding, unable to stand
- High fever (>104°F/40°C), seizures, severe pain

**General Care Tips:**
- Monitor appetite, behavior, and vital signs daily
- Ensure clean water and appropriate nutrition
- Maintain clean, dry living conditions
- Isolate sick animals to prevent spread

**Common Treatments:**
- Fever: Cool water, shade, electrolytes
- Minor cuts: Clean, disinfect, monitor healing
- Digestive issues: Withhold food briefly, provide water

**Always consult a qualified veterinarian for proper diagnosis and treatment.**"""
    
    def get_supported_languages(self):
        """Get list of supported languages"""
        return [
            {'code': 'en', 'name': 'English'},
            {'code': 'hi', 'name': 'Hindi'},
            {'code': 'mr', 'name': 'Marathi'},
            {'code': 'te', 'name': 'Telugu'},
            {'code': 'ta', 'name': 'Tamil'},
            {'code': 'bn', 'name': 'Bengali'},
            {'code': 'gu', 'name': 'Gujarati'},
            {'code': 'kn', 'name': 'Kannada'},
            {'code': 'ml', 'name': 'Malayalam'},
            {'code': 'pa', 'name': 'Punjabi'},
            {'code': 'es', 'name': 'Spanish'},
            {'code': 'fr', 'name': 'French'},
            {'code': 'de', 'name': 'German'}
        ]
    
    def clear_conversation(self, session_key=None):
        """Clear conversation history for a specific session or current session"""
        if session_key:
            if session_key in self.session_histories:
                del self.session_histories[session_key]
                logger.info(f"✅ Session {session_key} conversation history cleared")
            if self.current_session_key == session_key:
                self.conversation_history = []
                self.current_session_key = None
        else:
            # Clear current session
            if self.current_session_key and self.current_session_key in self.session_histories:
                del self.session_histories[self.current_session_key]
            self.conversation_history = []
            self.current_session_key = None
            logger.info("✅ Current conversation history cleared")
        
        return {'success': True, 'message': 'Conversation cleared'}
    
    def get_conversation_history(self, session_key=None):
        """Get conversation history for a specific session or current session"""
        if session_key:
            history = self.session_histories.get(session_key, [])
        else:
            history = self.conversation_history
            
        return {
            'success': True,
            'history': history[-10:],  # Return last 10 exchanges
            'session_key': session_key or self.current_session_key
        }
    
    def load_session_history(self, session_key):
        """Load conversation history for a specific session"""
        if session_key in self.session_histories:
            self.conversation_history = self.session_histories[session_key]
            self.current_session_key = session_key
            logger.info(f"✅ Loaded conversation history for session {session_key}")
        else:
            self.conversation_history = []
            self.session_histories[session_key] = self.conversation_history
            self.current_session_key = session_key
            logger.info(f"✅ Created new conversation history for session {session_key}")
        
        return {'success': True, 'session_key': session_key}
    
    def get_all_sessions(self):
        """Get all available session keys"""
        return {
            'success': True,
            'sessions': list(self.session_histories.keys()),
            'current_session': self.current_session_key
        }
    
    def health_check(self):
        """Check the health of the chatbot service"""
        status = {
            'genai_available': GENAI_AVAILABLE and self.model is not None,
            'vision_available': self.vision_model is not None,
            'pdf_available': PDF_AVAILABLE,
            'translation_available': TRANSLATION_AVAILABLE,
            'image_processing_available': IMAGE_PROCESSING_AVAILABLE
        }
        
        overall_health = any(status.values())
        
        return {
            'success': True,
            'healthy': overall_health,
            'services': status,
            'message': 'Service operational' if overall_health else 'Limited functionality'
        }