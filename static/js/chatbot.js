// =================== CHATBOT JAVASCRIPT ===================

class VeterinaryChatbot {
    constructor() {
        this.isRecording = false;
        this.recognition = null;
        this.synthesis = window.speechSynthesis;
        this.currentLanguage = 'en';
        this.voices = [];
        this.currentSessionKey = null; // Store current session key
        this.sessionHistory = {}; // Store chat history by session
        this.settings = {
            ttsEnabled: true,
            voiceInputEnabled: true,
            darkModeEnabled: false,
            autoScrollEnabled: true,
            voiceLanguage: 'en-US'
        };
        
        this.init();
    }

    init() {
        try {
            console.log('🚀 Starting chatbot initialization...');
            
            this.loadSettings();
            console.log('✅ Settings loaded');
            
            // Load session history from localStorage
            this.loadSessionFromStorage();
            console.log('✅ Session history loaded');
            
            this.setupEventListeners();
            console.log('✅ Event listeners setup complete');
            
            // Initialize speech features (non-critical)
            try {
                this.initializeSpeechRecognition();
                console.log('✅ Speech recognition initialized');
            } catch (speechError) {
                console.warn('⚠️ Speech recognition initialization failed:', speechError);
            }
            
            try {
                this.loadVoices();
                console.log('✅ Voices loaded');
            } catch (voiceError) {
                console.warn('⚠️ Voice loading failed:', voiceError);
            }
            
            try {
                this.loadLanguages();
                console.log('✅ Languages loading initiated');
            } catch (langError) {
                console.warn('⚠️ Language loading failed:', langError);
            }
            
            try {
                this.setupFileUpload();
                console.log('✅ File upload setup complete');
            } catch (fileError) {
                console.warn('⚠️ File upload setup failed:', fileError);
            }
            
            try {
                this.autoResizeTextarea();
                console.log('✅ Textarea auto-resize setup complete');
            } catch (resizeError) {
                console.warn('⚠️ Textarea resize setup failed:', resizeError);
            }
            
            // Set default language and voice (non-critical)
            try {
                this.updateVoiceLanguageForChat(this.currentLanguage);
                console.log('✅ Voice language updated');
            } catch (voiceLangError) {
                console.warn('⚠️ Voice language update failed:', voiceLangError);
            }
            
            // Check chatbot health (non-critical)
            try {
                this.checkChatbotHealth();
                console.log('✅ Health check initiated');
            } catch (healthError) {
                console.warn('⚠️ Health check failed:', healthError);
            }
            
            console.log('🎉 Veterinary Chatbot initialized successfully!');
            console.log('🌍 Current language:', this.currentLanguage);
            console.log('🗣️ Voice language:', this.settings.voiceLanguage);
            console.log('🔑 Current session:', this.currentSessionKey);
            
        } catch (error) {
            console.error('❌ Critical error during chatbot initialization:', error);
            console.error('Stack trace:', error.stack);
            
            // Try minimal initialization
            this.setupBasicEventListeners();
        }
    }

    setupBasicEventListeners() {
        console.log('🔧 Setting up BASIC event listeners only...');
        
        try {
            const sendBtn = document.getElementById('sendBtn');
            if (sendBtn) {
                sendBtn.addEventListener('click', () => {
                    console.log('📤 Send button clicked (basic mode)');
                    const input = document.getElementById('messageInput');
                    if (input && input.value.trim()) {
                        // Use toast instead of alert
                        this.showToast('Basic mode: ' + input.value.trim(), 'info');
                        input.value = '';
                    }
                });
                console.log('✅ Basic send button listener added');
            }
            
            const voiceBtn = document.getElementById('voiceBtn');
            if (voiceBtn) {
                voiceBtn.addEventListener('click', () => {
                    console.log('🎤 Voice button clicked (basic mode)');
                    // Use toast instead of alert
                    this.showToast('Voice feature temporarily unavailable', 'error');
                });
                console.log('✅ Basic voice button listener added');
            }
            
        } catch (basicError) {
            console.error('❌ Even basic event listeners failed:', basicError);
        }
    }

    // =================== SETTINGS MANAGEMENT ===================

    loadSettings() {
        try {
            console.log('📋 Loading settings...');
            const savedSettings = localStorage.getItem('chatbot-settings');
            if (savedSettings) {
                this.settings = { ...this.settings, ...JSON.parse(savedSettings) };
                console.log('✅ Settings loaded from localStorage');
            } else {
                console.log('ℹ️ No saved settings found, using defaults');
            }
            this.applySettings();
        } catch (error) {
            console.error('❌ Error loading settings:', error);
            console.log('🔄 Using default settings');
        }
    }

    saveSettings() {
        try {
            localStorage.setItem('chatbot-settings', JSON.stringify(this.settings));
            console.log('💾 Settings saved successfully');
        } catch (error) {
            console.error('❌ Error saving settings:', error);
        }
    }

    applySettings() {
        try {
            console.log('🎨 Applying settings...');
            
            // Apply dark mode
            if (this.settings.darkModeEnabled) {
                document.body.classList.add('dark-mode');
            } else {
                document.body.classList.remove('dark-mode');
            }

            // Apply other settings if elements exist
            const ttsCheckbox = document.getElementById('ttsEnabled');
            if (ttsCheckbox) {
                ttsCheckbox.checked = this.settings.ttsEnabled;
            }

            const voiceCheckbox = document.getElementById('voiceInputEnabled');
            if (voiceCheckbox) {
                voiceCheckbox.checked = this.settings.voiceInputEnabled;
            }

            const darkCheckbox = document.getElementById('darkModeEnabled');
            if (darkCheckbox) {
                darkCheckbox.checked = this.settings.darkModeEnabled;
            }

            const scrollCheckbox = document.getElementById('autoScrollEnabled');
            if (scrollCheckbox) {
                scrollCheckbox.checked = this.settings.autoScrollEnabled;
            }

            const voiceLanguageSelect = document.getElementById('voiceLanguageSelect');
            if (voiceLanguageSelect) {
                voiceLanguageSelect.value = this.settings.voiceLanguage;
            }
            
            console.log('✅ Settings applied successfully');
        } catch (error) {
            console.error('❌ Error applying settings:', error);
        }
    }

    // =================== EVENT LISTENERS ===================

    setupEventListeners() {
        console.log('🔧 Setting up event listeners...');
        
        // Send message
        const sendBtn = document.getElementById('sendBtn');
        const messageInput = document.getElementById('messageInput');
        
        if (sendBtn) {
            sendBtn.addEventListener('click', () => {
                console.log('📤 Send button clicked!');
                this.sendMessage();
            });
            console.log('✅ Send button listener added');
        } else {
            console.error('❌ Send button not found!');
        }

        if (messageInput) {
            messageInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    console.log('⌨️ Enter key pressed!');
                    this.sendMessage();
                }
            });
            
            messageInput.addEventListener('input', () => {
                this.updateSendButton();
                // Removed showSuggestions() to prevent popup during typing
                // this.showSuggestions();
            });
            console.log('✅ Message input listeners added');
        } else {
            console.error('❌ Message input not found!');
        }

        // Voice input
        const voiceBtn = document.getElementById('voiceBtn');
        if (voiceBtn) {
            voiceBtn.addEventListener('click', () => {
                console.log('🎤 Voice button clicked!');
                this.toggleVoiceInput();
            });
            console.log('✅ Voice button listener added');
        } else {
            console.error('❌ Voice button not found!');
        }

        // File upload
        const fileUploadBtn = document.getElementById('fileUploadBtn');
        if (fileUploadBtn) {
            fileUploadBtn.addEventListener('click', () => {
                console.log('📁 File upload button clicked!');
                this.triggerFileUpload();
            });
            console.log('✅ File upload button listener added');
        } else {
            console.error('❌ File upload button not found!');
        }

        // Clear chat
        // Clear chat button
        const clearChatBtn = document.getElementById('clearChatBtn');
        if (clearChatBtn) {
            clearChatBtn.addEventListener('click', () => {
                console.log('🗑️ Clear chat button clicked!');
                this.clearChat();
            });
            console.log('✅ Clear chat button listener added');
        } else {
            console.error('❌ Clear chat button not found!');
        }

        // New session button
        const newSessionBtn = document.getElementById('newSessionBtn');
        if (newSessionBtn) {
            newSessionBtn.addEventListener('click', () => {
                console.log('🆕 New session button clicked!');
                this.startNewSession();
            });
            console.log('✅ New session button listener added');
        } else {
            console.error('❌ New session button not found!');
        }

        // Settings
        const settingsBtn = document.getElementById('settingsBtn');
        const closeSettingsBtn = document.getElementById('closeSettingsBtn');
        const cancelSettingsBtn = document.getElementById('cancelSettingsBtn');
        
        if (settingsBtn) {
            settingsBtn.addEventListener('click', () => {
                console.log('⚙️ Settings button clicked!');
                this.openSettings();
            });
            console.log('✅ Settings button listener added');
        } else {
            console.error('❌ Settings button not found!');
        }
        
        if (closeSettingsBtn) {
            closeSettingsBtn.addEventListener('click', () => {
                console.log('❌ Close settings button clicked!');
                this.closeSettings();
            });
            console.log('✅ Close settings button listener added');
        } else {
            console.error('❌ Close settings button not found!');
        }

        if (cancelSettingsBtn) {
            cancelSettingsBtn.addEventListener('click', () => {
                console.log('❌ Cancel settings button clicked!');
                this.closeSettings();
            });
            console.log('✅ Cancel settings button listener added');
        } else {
            console.error('❌ Cancel settings button not found!');
        }

        // Settings changes - only add if elements exist
        this.setupSettingsListeners();

        // Language selector
        const languageSelect = document.getElementById('languageSelect');
        if (languageSelect) {
            languageSelect.addEventListener('change', (e) => {
                const newLang = e.target.value;
                console.log('🌍 Language changed to:', newLang);
                this.currentLanguage = newLang;
                
                // Update voice settings for the new language
                this.updateVoiceLanguageForChat(newLang);
                
                // Refresh voices to ensure we have the latest available
                this.loadVoices();
                
                // Show confirmation for Marathi selection
                if (newLang === 'mr') {
                    this.showToast('🇮🇳 मराठी भाषा निवडली गेली. आता आपण मराठीत प्रश्न विचारू शकता!', 'success');
                    console.log('🎯 Marathi language selected - TTS optimized for Marathi');
                }
            });
            console.log('✅ Language selector listener added');
        } else {
            console.error('❌ Language selector not found!');
        }

        // Quick actions
        this.setupQuickActions();

        // Input suggestions
        this.setupSuggestionListeners();

        console.log('✅ Event listeners setup completed');
    }

    setupSettingsListeners() {
        console.log('⚙️ Setting up settings listeners...');
        
        // Settings changes - only add if elements exist
        const ttsEnabled = document.getElementById('ttsEnabled');
        const voiceInputEnabled = document.getElementById('voiceInputEnabled');
        const darkModeEnabled = document.getElementById('darkModeEnabled');
        const autoScrollEnabled = document.getElementById('autoScrollEnabled');
        const voiceLanguageSelect = document.getElementById('voiceLanguageSelect');
        
        if (ttsEnabled) {
            ttsEnabled.addEventListener('change', (e) => {
                console.log('🔊 TTS setting changed:', e.target.checked);
                this.settings.ttsEnabled = e.target.checked;
                this.saveSettings();
            });
        }
        
        if (voiceInputEnabled) {
            voiceInputEnabled.addEventListener('change', (e) => {
                console.log('🎤 Voice input setting changed:', e.target.checked);
                this.settings.voiceInputEnabled = e.target.checked;
                this.saveSettings();
            });
        }
        
        if (darkModeEnabled) {
            darkModeEnabled.addEventListener('change', (e) => {
                console.log('🌙 Dark mode setting changed:', e.target.checked);
                this.settings.darkModeEnabled = e.target.checked;
                this.applySettings();
                this.saveSettings();
            });
        }
        
        if (autoScrollEnabled) {
            autoScrollEnabled.addEventListener('change', (e) => {
                console.log('📜 Auto-scroll setting changed:', e.target.checked);
                this.settings.autoScrollEnabled = e.target.checked;
                this.saveSettings();
            });
        }
        
        if (voiceLanguageSelect) {
            voiceLanguageSelect.addEventListener('change', (e) => {
                console.log('🗣️ Voice language setting changed:', e.target.value);
                this.settings.voiceLanguage = e.target.value;
                this.saveSettings();
            });
        }
    }

    setupQuickActions() {
        console.log('⚡ Setting up quick actions...');
        const quickActions = this.safeQuerySelectorAll('.quick-action');
        console.log(`Found ${quickActions.length} quick action buttons`);
        
        quickActions.forEach(btn => {
            if (btn && btn.addEventListener) {
                btn.addEventListener('click', (e) => {
                    const action = e.currentTarget.dataset.action;
                    console.log('⚡ Quick action clicked:', action);
                    this.handleQuickAction(action);
                });
            }
        });
    }

    setupSuggestionListeners() {
        console.log('💡 Setting up suggestion listeners...');
        const suggestions = this.safeQuerySelectorAll('.suggestion');
        console.log(`Found ${suggestions.length} suggestion items`);
        
        suggestions.forEach(suggestion => {
            if (suggestion && suggestion.addEventListener) {
                suggestion.addEventListener('click', (e) => {
                    const text = e.currentTarget.dataset.text;
                    console.log('💡 Suggestion clicked:', text);
                    const messageInput = document.getElementById('messageInput');
                    if (messageInput) {
                        messageInput.value = text;
                        this.updateSendButton();
                    }
                });
            }
        });
    }

    // =================== SPEECH RECOGNITION ===================

    initializeSpeechRecognition() {
        // Check if HTTPS is required and warn user
        if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
            console.warn('⚠️ Speech recognition may not work over HTTP. Consider using HTTPS.');
        }

        if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
            const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
            this.recognition = new SpeechRecognition();
            
            this.recognition.continuous = false;
            this.recognition.interimResults = true;
            this.recognition.maxAlternatives = 1;
            this.recognition.lang = this.settings.voiceLanguage || 'en-US';

            this.recognition.onstart = () => {
                console.log('🎤 Speech recognition started');
                this.isRecording = true;
                const voiceBtn = document.getElementById('voiceBtn');
                if (voiceBtn) {
                    voiceBtn.classList.add('recording');
                    const icon = this.safeQuerySelector(voiceBtn, 'i');
                    if (icon) {
                        icon.className = 'fas fa-stop';
                    }
                }
                this.showToast('🎤 Listening... Speak now', 'info');
            };

            this.recognition.onresult = (event) => {
                let transcript = '';
                for (let i = event.resultIndex; i < event.results.length; i++) {
                    const result = event.results[i];
                    if (result.isFinal) {
                        transcript += result[0].transcript;
                    }
                }
                
                if (transcript.trim()) {
                    console.log('🎤 Speech recognized:', transcript);
                    const messageInput = document.getElementById('messageInput');
                    if (messageInput) {
                        messageInput.value = transcript.trim();
                        this.updateSendButton();
                    }
                    this.hideToast('info');
                    this.showToast('✅ Speech captured successfully!', 'success');
                }
            };

            this.recognition.onerror = (event) => {
                console.error('Speech recognition error:', event.error);
                this.stopRecording();
                
                let errorMessage = 'Voice recognition error';
                switch (event.error) {
                    case 'network':
                        // Often 'network' errors are actually permission issues in disguise
                        errorMessage = '🎤 Microphone access issue - please click the microphone icon in your browser\'s address bar and allow access, then try again';
                        break;
                    case 'not-allowed':
                        errorMessage = 'Microphone access denied - please allow microphone permissions in your browser settings';
                        break;
                    case 'no-speech':
                        errorMessage = 'No speech detected - please speak clearly and try again';
                        break;
                    case 'audio-capture':
                        errorMessage = 'Audio capture failed - please check your microphone connection';
                        break;
                    case 'service-not-allowed':
                        errorMessage = 'Speech service not allowed - please check your browser settings';
                        break;
                    case 'bad-grammar':
                        errorMessage = 'Speech recognition grammar error - please try again';
                        break;
                    case 'language-not-supported':
                        errorMessage = 'Selected language not supported for speech recognition';
                        break;
                    default:
                        errorMessage = `Voice recognition error: ${event.error}. Please check microphone permissions and try again.`;
                }
                this.showToast('❌ ' + errorMessage, 'error');
            };

            this.recognition.onend = () => {
                console.log('🎤 Speech recognition ended');
                this.stopRecording();
            };
        } else {
            console.warn('Speech recognition not supported in this browser');
            this.settings.voiceInputEnabled = false;
            this.showToast('❌ Speech recognition not supported in this browser', 'error');
        }
    }

    async toggleVoiceInput() {
        if (!this.settings.voiceInputEnabled) {
            this.showToast('❌ Voice input is disabled in settings', 'error');
            return;
        }

        if (!this.recognition) {
            this.showToast('❌ Voice recognition not supported in this browser', 'error');
            return;
        }

        try {
            if (this.isRecording) {
                console.log('🛑 Stopping voice recognition');
                this.recognition.stop();
            } else {
                console.log('🎤 Starting voice recognition');
                
                // Check microphone permission first
                await this.checkMicrophonePermission();
                
                this.recognition.lang = this.settings.voiceLanguage || 'en-US';
                this.recognition.start();
            }
        } catch (error) {
            console.error('Voice recognition error:', error);
            if (error.message.includes('Microphone access denied')) {
                this.showToast('❌ Microphone access denied - please allow microphone permissions in your browser settings', 'error');
            } else if (error.message.includes('No microphone found')) {
                this.showToast('❌ No microphone found - please connect a microphone and try again', 'error');
            } else {
                this.showToast('❌ Failed to start voice recognition: ' + error.message, 'error');
            }
            this.stopRecording();
        }
    }

    async checkMicrophonePermission() {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            throw new Error('MediaDevices not supported in this browser');
        }

        try {
            // Try to get microphone access
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            // Stop the stream immediately as we just needed to check permission
            stream.getTracks().forEach(track => track.stop());
            console.log('✅ Microphone permission granted');
            return true;
        } catch (error) {
            console.error('Microphone permission check failed:', error);
            if (error.name === 'NotAllowedError') {
                throw new Error('Microphone access denied by user');
            } else if (error.name === 'NotFoundError') {
                throw new Error('No microphone found');
            } else if (error.name === 'NotSupportedError') {
                throw new Error('Microphone not supported');
            } else if (error.name === 'NotReadableError') {
                throw new Error('Microphone is being used by another application');
            } else {
                throw new Error('Microphone access failed: ' + error.message);
            }
        }
    }

    stopRecording() {
        this.isRecording = false;
        const voiceBtn = document.getElementById('voiceBtn');
        if (voiceBtn) {
            voiceBtn.classList.remove('recording');
            const icon = this.safeQuerySelector(voiceBtn, 'i');
            if (icon) {
                icon.className = 'fas fa-microphone';
            }
        }
        this.hideToast('info');
    }

    // =================== TEXT-TO-SPEECH ===================

    loadVoices() {
        const updateVoices = () => {
            this.voices = this.synthesis.getVoices();
            console.log(`🔊 Loaded ${this.voices.length} voices`);
            
            // Log available languages for debugging
            if (this.voices.length > 0) {
                const languages = [...new Set(this.voices.map(v => v.lang))].sort();
                console.log('🌍 Available voice languages:', languages);
                
                // Check for Indian languages specifically
                const indianLangs = languages.filter(lang => lang.includes('-IN'));
                if (indianLangs.length > 0) {
                    console.log('🇮🇳 Indian language voices found:', indianLangs);
                }
                
                // Look specifically for Marathi or Marathi-compatible voices
                const marathiVoices = this.voices.filter(voice => 
                    voice.lang.toLowerCase().includes('mr') || 
                    voice.name.toLowerCase().includes('marathi') ||
                    voice.lang.toLowerCase() === 'hi-in' // Hindi can work as fallback
                );
                
                if (marathiVoices.length > 0) {
                    console.log('🎯 Marathi-compatible voices found:');
                    marathiVoices.forEach(voice => {
                        console.log(`  - ${voice.name} (${voice.lang}) ${voice.default ? '[DEFAULT]' : ''}`);
                    });
                } else {
                    console.warn('⚠️ No Marathi-compatible voices found. TTS may fall back to system default.');
                }
            }
        };
        
        updateVoices();
        
        // Voices might load asynchronously
        if (this.voices.length === 0) {
            this.synthesis.onvoiceschanged = updateVoices;
        }
    }

    // =================== HELPER FUNCTIONS ===================
    
    safeQuerySelector(element, selector) {
        try {
            if (!element) return null;
            return element.querySelector(selector);
        } catch (error) {
            console.warn(`⚠️ QuerySelector error for "${selector}":`, error);
            return null;
        }
    }
    
    safeQuerySelectorAll(selector) {
        try {
            return document.querySelectorAll(selector) || [];
        } catch (error) {
            console.warn(`⚠️ QuerySelectorAll error for "${selector}":`, error);
            return [];
        }
    }

    // =================== DEBUG FUNCTIONS ===================
    
    // Test TTS in different languages (call from browser console: chatbot.testTTS('hi'))
    testTTS(langCode = 'en') {
        console.log(`🧪 Testing TTS for language: ${langCode}`);
        
        // Update language temporarily
        const originalLang = this.currentLanguage;
        this.currentLanguage = langCode;
        this.updateVoiceLanguageForChat(langCode);
        
        // Test phrases for different languages
        const testPhrases = {
            'en': 'Hello, this is a test of English text to speech.',
            'hi': 'नमस्ते, यह हिंदी टेक्स्ट टू स्पीच का परीक्षण है।',
            'mr': 'नमस्कार, हे मराठी मजकूर ते भाषण चाचणी आहे।',
            'ta': 'வணக்கம், இது தமிழ் உரை மொழி சோதனை ஆகும்।',
            'te': 'నమస్కారం, ఇది తెలుగు టెక్స్ట్ టు స్పీచ్ పరీక్ష।'
        };
        
        const testText = testPhrases[langCode] || testPhrases['en'];
        console.log(`🔊 Speaking: "${testText}"`);
        this.speak(testText);
        
        // Restore original language after a delay
        setTimeout(() => {
            this.currentLanguage = originalLang;
            this.updateVoiceLanguageForChat(originalLang);
        }, 100);
    }
    
    // List all available voices (call from console: chatbot.listVoices())
    listVoices() {
        console.log('🔊 All available voices:');
        this.voices.forEach((voice, index) => {
            console.log(`${index + 1}. ${voice.name} (${voice.lang}) - ${voice.default ? 'DEFAULT' : 'available'}`);
        });
        return this.voices;
    }

    // Test Marathi TTS specifically (call from console: chatbot.testMarathiTTS())
    testMarathiTTS() {
        console.log('🧪 Testing Marathi TTS specifically...');
        
        // Update to Marathi temporarily
        const originalLang = this.currentLanguage;
        this.currentLanguage = 'mr';
        this.updateVoiceLanguageForChat('mr');
        
        // Test with natural Marathi veterinary text that showcases improvements
        const marathiTest = 'नमस्कार। माझ्या गायीला ताप आहे। मी काय करावे? डॉक्टरांना दाखवावे का?';
        console.log('🎯 Testing improved natural Marathi TTS:', marathiTest);
        
        // Force refresh voices
        this.loadVoices();
        
        setTimeout(() => {
            console.log('🔊 Speaking improved natural Marathi...');
            this.speak(marathiTest);
            
            // Also test a longer sentence with medical terms
            setTimeout(() => {
                const medicalTest = 'गाय रुग्ण आहे। तिला उपचार पाहिजे आणि औषध द्यावे लागेल।';
                console.log('🔊 Testing medical Marathi terms:', medicalTest);
                this.speak(medicalTest);
                
                // Restore original language after all tests
                setTimeout(() => {
                    this.currentLanguage = originalLang;
                    this.updateVoiceLanguageForChat(originalLang);
                    console.log('✅ Enhanced Marathi TTS test completed');
                }, 4000);
            }, 4000);
        }, 1000);
    }

    // Debug voice capabilities for Indian languages (call from console: chatbot.debugIndianVoices())
    debugIndianVoices() {
        console.log('🔍 Debugging Indian language voice support...');
        
        const voices = this.synthesis.getVoices();
        console.log(`📋 Total voices available: ${voices.length}`);
        
        // Check for Indian languages
        const indianVoices = voices.filter(voice => 
            voice.lang.includes('-IN') || 
            /hindi|marathi|tamil|telugu|gujarati|kannada|malayalam|bengali|punjabi/i.test(voice.name)
        );
        
        if (indianVoices.length > 0) {
            console.log('🇮🇳 Indian language voices found:');
            indianVoices.forEach((voice, index) => {
                console.log(`  ${index + 1}. ${voice.name} (${voice.lang}) ${voice.default ? '[DEFAULT]' : ''}`);
            });
        } else {
            console.log('❌ No Indian language voices found');
            console.log('💡 Suggestions:');
            console.log('   1. Install language packs in Windows Settings');
            console.log('   2. Try Microsoft Edge browser (better Indian language support)');
            console.log('   3. Add Hindi language pack to your system');
        }
        
        // Check speech synthesis support
        if (!window.speechSynthesis) {
            console.log('❌ Speech synthesis not supported in this browser');
        } else {
            console.log('✅ Speech synthesis is supported');
        }
        
        return {
            totalVoices: voices.length,
            indianVoices: indianVoices.length,
            speechSynthesisSupported: !!window.speechSynthesis
        };
    }

    speak(text) {
        if (!this.settings.ttsEnabled || !text || !text.trim()) {
            console.log('🔇 TTS disabled or empty text');
            return;
        }

        try {
            // Stop any ongoing speech
            this.synthesis.cancel();

            // Clean up text for better speech
            let cleanText = text
                .replace(/[🔥🩺💉🐄🐮🐎🐑🐷🐔🌡️💧😷🦵🥛]/g, '') // Remove emojis
                .replace(/\*\*(.*?)\*\*/g, '$1') // Remove markdown bold
                .replace(/\*(.*?)\*/g, '$1') // Remove markdown italic
                .replace(/`(.*?)`/g, '$1') // Remove code blocks
                .replace(/[\[\]()]/g, '') // Remove brackets and parentheses
                .trim();

            // For Marathi, add enhanced preprocessing for more natural pronunciation
            if (this.currentLanguage === 'mr') {
                // First, preserve important Marathi sentence structure
                cleanText = cleanText
                    // Replace common English technical terms with pauses for better flow
                    .replace(/\b(temperature|fever|symptoms?|treatment|medicine|doctor|veterinary)\b/gi, ' ')
                    // Convert numbers to Marathi words for better pronunciation
                    .replace(/\b1\b/g, 'एक')
                    .replace(/\b2\b/g, 'दोन') 
                    .replace(/\b3\b/g, 'तीन')
                    .replace(/\b4\b/g, 'चार')
                    .replace(/\b5\b/g, 'पाच')
                    // Improve common Marathi word pronunciation
                    .replace(/गाय/g, 'गाय') // Ensure proper cow pronunciation
                    .replace(/रुग्ण/g, 'रुग्ण') // Patient
                    .replace(/औषध/g, 'औषध') // Medicine  
                    .replace(/डॉक्टर/g, 'डॉक्टर') // Doctor
                    .replace(/उपचार/g, 'उपचार') // Treatment
                    // Add natural pauses around connecting words
                    .replace(/\b(आणि|किंवा|तसेच|म्हणून|परंतु)\b/g, '। $1 ।')
                    // Keep essential punctuation for natural pauses
                    .replace(/[.,;]/g, '। ') // Replace with Devanagari full stop for natural pause
                    .replace(/[!?]/g, '॥ ') // Use double danda for exclamatory pauses
                    .replace(/[:]/g, ' - ') // Replace colons with dash
                    // Add natural breathing pauses after common Marathi sentence patterns
                    .replace(/(आहे|होते|केले|करावे|पाहिजे|असावे|झाले)/g, '$1। ')
                    // Handle common conjunctions better
                    .replace(/(तर|अगर|जर|जेव्हा)/g, '$1 ')
                    // Clean up extra spaces while preserving natural pauses
                    .replace(/\s+/g, ' ')
                    .replace(/।\s*।/g, '।') // Remove duplicate pauses
                    .trim();
                
                console.log(`🔊 Marathi text processed for natural speech: "${cleanText.substring(0, 100)}..."`);
            }

            if (!cleanText) return;

            const utterance = new SpeechSynthesisUtterance(cleanText);
            
            // Enhanced voice selection for Marathi
            if (this.currentLanguage === 'mr') {
                console.log('🔊 Setting up enhanced Marathi TTS...');
                
                // Force refresh voices to ensure we have the latest list
                const voices = window.speechSynthesis.getVoices();
                
                // Look for Marathi voices with priority ranking for quality
                let marathiVoice = null;
                
                // Priority order for Marathi voice selection (highest to lowest quality)
                const marathiVoiceSelectors = [
                    // Tier 1: Native Marathi voices
                    { pattern: /^mr-IN/i, priority: 10, desc: 'Native Marathi India' },
                    { pattern: /marathi.*india/i, priority: 9, desc: 'Marathi India voice' },
                    { pattern: /^mr/i, priority: 8, desc: 'Marathi voice' },
                    
                    // Tier 2: High-quality Hindi voices (better pronunciation for Devanagari)
                    { pattern: /^hi-IN.*(?:female|google|microsoft)/i, priority: 7, desc: 'Premium Hindi India (female)' },
                    { pattern: /^hi-IN/i, priority: 6, desc: 'Hindi India voice' },
                    
                    // Tier 3: Other Indian voices
                    { pattern: /india.*devanagari/i, priority: 5, desc: 'India Devanagari voice' },
                    { pattern: /^hi/i, priority: 4, desc: 'Hindi voice' },
                    
                    // Tier 4: Fallback
                    { pattern: /en-IN/i, priority: 3, desc: 'English India (fallback)' }
                ];
                
                let bestVoice = null;
                let bestPriority = 0;
                
                for (const selector of marathiVoiceSelectors) {
                    const candidateVoices = voices.filter(voice => 
                        selector.pattern.test(voice.lang) || selector.pattern.test(voice.name)
                    );
                    
                    if (candidateVoices.length > 0) {
                        // Prefer non-default voices as they're often higher quality
                        const preferredVoice = candidateVoices.find(v => !v.default) || candidateVoices[0];
                        
                        if (selector.priority > bestPriority) {
                            bestVoice = preferredVoice;
                            bestPriority = selector.priority;
                            console.log(`✅ Found ${selector.desc}: ${preferredVoice.name} (${preferredVoice.lang})`);
                        }
                    }
                }
                
                marathiVoice = bestVoice;
                
                if (marathiVoice) {
                    utterance.voice = marathiVoice;
                    utterance.lang = marathiVoice.lang;
                    
                    // Optimized settings for natural Marathi pronunciation
                    utterance.rate = 0.8;    // Slightly slower for clarity and natural flow
                    utterance.pitch = 1.0;   // Natural pitch for Marathi
                    utterance.volume = 0.95; // Clear volume
                    
                    console.log(`🎯 Selected best Marathi voice: ${marathiVoice.name} (${marathiVoice.lang}) - Priority: ${bestPriority}`);
                } else {
                    // Fallback: use manual language setting
                    utterance.lang = 'mr-IN';
                    utterance.rate = 0.7;   // Even slower for fallback
                    utterance.pitch = 1.0;  
                    utterance.volume = 0.9;
                    console.log('⚠️ No Marathi voice found, using language code mr-IN');
                }
            } else {
                // Use existing logic for non-Marathi languages
                const voiceLang = this.settings.voiceLanguage || 'en-US';
                console.log(`🔊 Speaking in language: ${voiceLang} (chat language: ${this.currentLanguage})`);
                
                if (this.settings.selectedVoice) {
                    utterance.voice = this.settings.selectedVoice;
                    utterance.lang = this.settings.selectedVoice.lang;
                    console.log(`🔊 Using pre-selected voice: ${this.settings.selectedVoice.name} (${this.settings.selectedVoice.lang})`);
                } else {
                    // Find the best matching voice for the selected language
                    let voice = null;
                    
                    voice = this.voices.find(v => 
                        v.lang.toLowerCase() === voiceLang.toLowerCase()
                    );
                    
                    if (!voice) {
                        const langCode = voiceLang.split('-')[0];
                        voice = this.voices.find(v => 
                            v.lang.toLowerCase().startsWith(langCode.toLowerCase())
                        );
                    }
                    
                    if (!voice) {
                        voice = this.voices.find(v => v.lang.startsWith('en'));
                        console.warn(`⚠️ No voice found for ${voiceLang}, falling back to English`);
                    }
                    
                    if (voice) {
                        utterance.voice = voice;
                        utterance.lang = voice.lang;
                        this.settings.selectedVoice = voice;
                        console.log(`🔊 Selected and cached voice: ${voice.name} (${voice.lang})`);
                    } else {
                        utterance.lang = voiceLang;
                        console.log(`🔊 No specific voice found, using language: ${voiceLang}`);
                    }
                }
                
                utterance.rate = 0.9;
                utterance.pitch = 1;
                utterance.volume = 0.8;
            }

            utterance.onstart = () => {
                console.log('🔊 TTS started');
            };

            utterance.onend = () => {
                console.log('🔊 TTS ended');
            };

            utterance.onerror = (event) => {
                console.error('TTS error:', event.error);
                
                // If TTS fails for Marathi, try with a different approach
                if (this.currentLanguage === 'mr') {
                    console.log('🔄 Retrying Marathi TTS with different settings...');
                    
                    setTimeout(() => {
                        const fallbackUtterance = new SpeechSynthesisUtterance(cleanText);
                        fallbackUtterance.lang = 'hi-IN'; // Try Hindi as fallback
                        fallbackUtterance.rate = 0.6;
                        fallbackUtterance.pitch = 0.9;
                        fallbackUtterance.volume = 0.9;
                        
                        console.log('🔄 Attempting fallback with Hindi voice...');
                        this.synthesis.speak(fallbackUtterance);
                    }, 500);
                }
            };

            console.log(`🎯 Speaking Marathi text: "${cleanText.substring(0, 50)}..." in ${utterance.lang}`);
            this.synthesis.speak(utterance);
        } catch (error) {
            console.error('Text-to-speech error:', error);
        }
    }

    // =================== LANGUAGE MANAGEMENT ===================

    updateVoiceLanguageForChat(languageCode) {
        // Map chat language codes to speech recognition language codes
        const langMap = {
            'en': 'en-US',
            'hi': 'hi-IN',
            'mr': 'mr-IN',
            'te': 'te-IN',
            'ta': 'ta-IN',
            'bn': 'bn-IN',
            'gu': 'gu-IN',
            'kn': 'kn-IN',
            'ml': 'ml-IN',
            'pa': 'pa-IN',
            'es': 'es-ES',
            'fr': 'fr-FR',
            'de': 'de-DE'
        };
        
        const voiceLang = langMap[languageCode] || 'en-US';
        this.settings.voiceLanguage = voiceLang;
        this.saveSettings();
        
        // Update speech recognition language if available
        if (this.recognition) {
            this.recognition.lang = voiceLang;
            console.log(`🎤 Speech recognition language updated to: ${voiceLang}`);
        }
        
        // Update voice language selector if it exists
        const voiceSelect = document.getElementById('voiceLanguageSelect');
        if (voiceSelect) {
            voiceSelect.value = voiceLang;
        }
        
        // Force voice selection to update for the new language
        this.selectVoiceForLanguage(voiceLang);
        
        console.log(`🗣️ Voice language updated to: ${voiceLang} for chat language: ${languageCode}`);
    }

    async loadLanguages() {
        try {
            const response = await fetch('/api/chat/languages');
            const data = await response.json();
            
            if (data.success) {
                const select = document.getElementById('languageSelect');
                select.innerHTML = '';
                
                Object.entries(data.languages).forEach(([code, name]) => {
                    const option = document.createElement('option');
                    option.value = code;
                    option.textContent = name;
                    select.appendChild(option);
                });
            }
        } catch (error) {
            console.error('Error loading languages:', error);
        }
    }

    // =================== MESSAGE HANDLING ===================

    async sendMessage() {
        const input = document.getElementById('messageInput');
        const message = input.value.trim();

        if (!message) return;

        // Generate session key if not exists
        if (!this.currentSessionKey) {
            this.currentSessionKey = `chat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            console.log('🔑 Generated new session key:', this.currentSessionKey);
        }

        // Add user message to chat
        this.addMessage('user', message);
        
        // Store message in session history
        this.storeMessageInSession('user', message);
        
        // Clear input
        input.value = '';
        this.updateSendButton();
        
        // Show typing indicator
        this.showTypingIndicator();

        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    message: message,
                    language: this.currentLanguage,
                    session_key: this.currentSessionKey
                })
            });

            const data = await response.json();
            
            if (data.success) {
                this.hideTypingIndicator();
                this.addMessage('bot', data.response);
                this.speak(data.response);
                
                // Store bot response in session history
                this.storeMessageInSession('bot', data.response);
                
                // Update session key if provided
                if (data.session_key) {
                    this.currentSessionKey = data.session_key;
                }
            } else {
                this.hideTypingIndicator();
                // Handle improved error responses
                if (data.fallback_response) {
                    this.addMessage('bot', data.fallback_response);
                    this.speak(data.fallback_response);
                    this.storeMessageInSession('bot', data.fallback_response);
                } else {
                    const errorMsg = `❌ ${data.error || 'Sorry, I encountered an error. Please try again.'}`;
                    this.addMessage('bot', errorMsg);
                    this.storeMessageInSession('bot', errorMsg);
                }
                
                // Show error toast with more detail
                this.showToast(data.error || 'Service temporarily unavailable', 'error');
                console.error('Chat error:', data.error);
            }
        } catch (error) {
            console.error('Error sending message:', error);
            this.hideTypingIndicator();
            
            // More helpful error message for network issues
            const errorMessage = error.message.includes('fetch') 
                ? 'Unable to connect to the server. Please check your internet connection and try again.'
                : `An error occurred: ${error.message}`;
            
            const finalErrorMsg = `❌ ${errorMessage}`;
            this.addMessage('bot', finalErrorMsg);
            this.storeMessageInSession('bot', finalErrorMsg);
            this.showToast('Connection failed: ' + error.message, 'error');
        }
    }

    addMessage(sender, text, storeInSession = true) {
        const messagesContainer = document.getElementById('chatMessages');
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${sender}-message`;

        const timestamp = new Date().toLocaleTimeString();
        
        messageDiv.innerHTML = `
            <div class="message-avatar">
                <i class="fas ${sender === 'user' ? 'fa-user' : 'fa-user-md'}"></i>
            </div>
            <div class="message-content">
                <div class="message-text">${this.formatMessage(text)}</div>
                <div class="message-timestamp">${timestamp}</div>
            </div>
        `;

        messagesContainer.appendChild(messageDiv);
        
        // Store in session if requested (default true)
        if (storeInSession) {
            this.storeMessageInSession(sender, text);
        }
        
        if (this.settings.autoScrollEnabled) {
            this.scrollToBottom();
        }
    }

    formatMessage(text) {
        // First, escape HTML special characters to prevent XSS
        text = text.replace(/&/g, '&amp;')
                  .replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;')
                  .replace(/"/g, '&quot;')
                  .replace(/'/g, '&#39;');
        
        // Convert markdown-like formatting
        text = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        text = text.replace(/\*(.*?)\*/g, '<em>$1</em>');
        text = text.replace(/`(.*?)`/g, '<code>$1</code>');
        
        // Handle numbered lists (1. 2. 3. etc.)
        text = text.replace(/^\d+\.\s+(.+)$/gm, '<li>$1</li>');
        
        // Handle bullet points (- or •)
        text = text.replace(/^[-•]\s+(.+)$/gm, '<li>$1</li>');
        
        // Wrap consecutive list items in <ul> tags
        text = text.replace(/(<li>.*<\/li>)/gs, function(match) {
            return '<ul>' + match + '</ul>';
        });
        
        // Fix nested ul tags (remove duplicate ul tags)
        text = text.replace(/<\/ul>\s*<ul>/g, '');
        
        // Handle section headers (lines ending with :)
        text = text.replace(/^([^:\n]+):$/gm, '<h4>$1:</h4>');
        
        // Handle treatment sections and symptoms
        text = text.replace(/^(Common Treatments?|Symptoms?|Prevention|When to see|Treatment|Immediate Actions?|Ongoing Treatment|Monitoring):\s*$/gim, '<h4>$1:</h4>');
        
        // Convert double line breaks to paragraph breaks
        text = text.replace(/\n\n+/g, '</p><p>');
        
        // Convert single line breaks to <br> tags
        text = text.replace(/\n/g, '<br>');
        
        // Wrap content in paragraphs if it doesn't start with a tag
        if (!text.trim().startsWith('<')) {
            text = '<p>' + text + '</p>';
        }
        
        // Clean up empty paragraphs
        text = text.replace(/<p>\s*<\/p>/g, '');
        text = text.replace(/<p>\s*<br>\s*<\/p>/g, '');
        
        // Ensure proper paragraph structure around headers
        text = text.replace(/<\/p><h4>/g, '</p><h4>');
        text = text.replace(/<\/h4><p>/g, '</h4><p>');
        
        return text;
    }

    showTypingIndicator() {
        const messagesContainer = document.getElementById('chatMessages');
        const typingDiv = document.createElement('div');
        typingDiv.className = 'message bot-message';
        typingDiv.id = 'typingIndicator';

        typingDiv.innerHTML = `
            <div class="message-avatar">
                <i class="fas fa-user-md"></i>
            </div>
            <div class="message-content">
                <div class="typing-indicator">
                    <span>AI is thinking</span>
                    <div class="typing-dots">
                        <div class="typing-dot"></div>
                        <div class="typing-dot"></div>
                        <div class="typing-dot"></div>
                    </div>
                </div>
            </div>
        `;

        messagesContainer.appendChild(typingDiv);
        this.scrollToBottom();
    }

    hideTypingIndicator() {
        const typingIndicator = document.getElementById('typingIndicator');
        if (typingIndicator) {
            typingIndicator.remove();
        }
    }

    // =================== FILE HANDLING ===================

    setupFileUpload() {
        try {
            console.log('📁 Setting up file upload...');
            
            const fileInput = document.getElementById('fileInput');
            const uploadArea = document.getElementById('fileUploadArea');

            if (fileInput) {
                fileInput.addEventListener('change', (e) => this.handleFileSelect(e.target.files));
                console.log('✅ File input event listener added');
            } else {
                console.warn('⚠️ File input element not found');
            }

            // Upload area is no longer used for interaction - kept for potential future drag/drop
            if (uploadArea) {
                console.log('✅ Upload area element found (not used for click interaction)');
            } else {
                console.warn('⚠️ Upload area element not found');
            }
        } catch (error) {
            console.error('❌ Error setting up file upload:', error);
        }
    }

    triggerFileUpload() {
        // Directly open file picker without showing the drop area
        document.getElementById('fileInput').click();
    }

    async handleFileSelect(files) {
        if (files.length === 0) return;

        const file = files[0];
        const maxSize = 16 * 1024 * 1024; // 16MB

        if (file.size > maxSize) {
            this.showToast('File too large. Maximum size is 16MB.', 'error');
            return;
        }

        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'application/pdf'];
        if (!allowedTypes.includes(file.type)) {
            this.showToast('Unsupported file type. Please upload images or PDF files.', 'error');
            return;
        }

        // Hide upload area
        document.getElementById('fileUploadArea').style.display = 'none';

        // Show file info message
        this.addMessage('user', `📎 Uploaded file: ${file.name} (${this.formatFileSize(file.size)})`);

        // Show immediate processing message instead of spinner
        this.addMessage('bot', '🔍 Analyzing your file, please wait...');

        try {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('language', this.currentLanguage);
            formData.append('question', 'Please analyze this file and provide insights about animal health or disease information.');

            const response = await fetch('/api/chat/upload', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            // Remove the "analyzing" message safely
            try {
                const messages = document.getElementById('chatMessages');
                if (messages) {
                    const lastMessage = messages.lastElementChild;
                    if (lastMessage && lastMessage.textContent && lastMessage.textContent.includes('Analyzing your file')) {
                        lastMessage.remove();
                    }
                }
            } catch (removeError) {
                console.warn('Could not remove analyzing message:', removeError);
            }

            if (data.success) {
                this.addMessage('bot', data.response);
                this.speak(data.response);
                
                if (data.type === 'image_analysis') {
                    this.showSidePanel('Image Analysis Results', data.response);
                }
            } else {
                // Handle improved error responses
                if (data.fallback_response) {
                    this.addMessage('bot', data.fallback_response);
                    this.speak(data.fallback_response);
                } else {
                    this.addMessage('bot', `❌ ${data.error || 'File analysis failed'}`);
                }
                
                // Show error toast with more detail
                this.showToast(data.error || 'File analysis service unavailable', 'error');
                console.error('File analysis error:', data.error);
            }
        } catch (error) {
            console.error('Error uploading file:', error);
            
            // Remove the "analyzing" message safely
            try {
                const messages = document.getElementById('chatMessages');
                if (messages) {
                    const lastMessage = messages.lastElementChild;
                    if (lastMessage && lastMessage.textContent && lastMessage.textContent.includes('Analyzing your file')) {
                        lastMessage.remove();
                    }
                }
            } catch (removeError) {
                console.warn('Could not remove analyzing message:', removeError);
            }
            
            this.addMessage('bot', '❌ I encountered an error analyzing your file. Please try again.');
            this.showToast('File upload failed: ' + (error.message || 'Unknown error'), 'error');
        }
        // No finally block needed since we removed hideLoading()
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // =================== UI HELPERS ===================

    updateSendButton() {
        const input = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');
        const hasText = input.value.trim().length > 0;
        
        sendBtn.disabled = !hasText;
        sendBtn.style.opacity = hasText ? '1' : '0.5';
    }

    showSuggestions() {
        const input = document.getElementById('messageInput');
        const suggestions = document.getElementById('inputSuggestions');
        
        if (input.value.length > 2 && input.value.length < 10) {
            suggestions.style.display = 'block';
        } else {
            suggestions.style.display = 'none';
        }
    }

    autoResizeTextarea() {
        try {
            const textarea = document.getElementById('messageInput');
            
            if (textarea) {
                textarea.addEventListener('input', () => {
                    textarea.style.height = 'auto';
                    textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
                });
                console.log('✅ Textarea auto-resize enabled');
            } else {
                console.warn('⚠️ Message input textarea not found');
            }
        } catch (error) {
            console.error('❌ Error setting up textarea auto-resize:', error);
        }
    }

    scrollToBottom() {
        try {
            const messagesContainer = document.getElementById('chatMessages');
            if (messagesContainer) {
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            }
        } catch (error) {
            console.error('❌ Error scrolling to bottom:', error);
        }
    }

    // =================== CHATBOT HEALTH ===================

    async checkChatbotHealth() {
        try {
            const response = await fetch('/api/chat/health');
            const data = await response.json();
            
            if (data.success && data.healthy) {
                console.log('✅ Chatbot service is healthy');
                console.log('🔧 Available services:', data.services);
            } else {
                console.warn('⚠️ Chatbot service issues detected:', data.message);
                this.showToast(`⚠️ Some chatbot features may be limited: ${data.message}`, 'info', 3000);
            }
        } catch (error) {
            console.error('❌ Failed to check chatbot health:', error);
            this.showToast('⚠️ Unable to verify chatbot status. Some features may be limited.', 'error', 5000);
        }
    }

    // =================== TTS VOICE MANAGEMENT ===================

    selectVoiceForLanguage(targetLanguage) {
        if (!window.speechSynthesis) {
            console.warn('⚠️ Speech synthesis not supported');
            return;
        }

        const voices = window.speechSynthesis.getVoices();
        console.log(`🔍 Selecting voice for language: ${targetLanguage} from ${voices.length} available voices`);

        // First try exact language match
        let selectedVoice = voices.find(voice => voice.lang === targetLanguage);
        
        // If no exact match, try language code match (e.g., 'hi-IN' matches 'hi')
        if (!selectedVoice) {
            const langCode = targetLanguage.split('-')[0];
            selectedVoice = voices.find(voice => voice.lang.startsWith(langCode));
        }

        // Default to English if no match found
        if (!selectedVoice) {
            selectedVoice = voices.find(voice => voice.lang.startsWith('en'));
        }

        if (selectedVoice) {
            this.settings.selectedVoice = selectedVoice;
            console.log(`✅ Selected voice: ${selectedVoice.name} (${selectedVoice.lang})`);
        } else {
            console.warn('⚠️ No suitable voice found, using system default');
        }
    }

    // =================== QUICK ACTIONS ===================

    handleQuickAction(action) {
        const messages = {
            symptoms: "What are the common symptoms I should look for in sick animals?",
            treatment: "Can you guide me through basic treatment options for common animal diseases?",
            prevention: "What prevention measures should I take to keep my animals healthy?",
            emergency: "I think my animal has an emergency. What should I do immediately?"
        };

        const message = messages[action];
        if (message) {
            document.getElementById('messageInput').value = message;
            this.updateSendButton();
        }
    }

    // =================== CHAT MANAGEMENT ===================

    async clearChat() {
        if (!confirm('Are you sure you want to clear the current chat session? This will remove all messages in this conversation.')) return;

        await this.clearCurrentSession();
    }

    // =================== MODALS ===================

    showLoading(text = 'Processing...') {
        const modal = document.getElementById('loadingModal');
        const loadingText = document.getElementById('loadingText');
        loadingText.textContent = text;
        modal.style.display = 'flex';
    }

    hideLoading() {
        document.getElementById('loadingModal').style.display = 'none';
    }

    openSettings() {
        document.getElementById('settingsModal').style.display = 'flex';
    }

    closeSettings() {
        document.getElementById('settingsModal').style.display = 'none';
    }

    showSidePanel(title, content) {
        const panel = document.getElementById('sidePanel');
        if (!panel) {
            console.warn('⚠️ Side panel element not found');
            return;
        }
        
        const header = this.safeQuerySelector(panel, '.side-panel-header h3');
        const contentDiv = document.getElementById('sidePanelContent');
        
        if (header) {
            header.textContent = title;
        }
        
        if (contentDiv) {
            contentDiv.innerHTML = `<div class="analysis-content">${this.formatMessage(content)}</div>`;
        }
        
        panel.style.display = 'flex';
    }

    closeSidePanel() {
        document.getElementById('sidePanel').style.display = 'none';
    }

    // =================== SESSION MANAGEMENT ===================

    storeMessageInSession(sender, message) {
        if (!this.currentSessionKey) return;
        
        if (!this.sessionHistory[this.currentSessionKey]) {
            this.sessionHistory[this.currentSessionKey] = [];
        }
        
        this.sessionHistory[this.currentSessionKey].push({
            sender: sender,
            message: message,
            timestamp: new Date().toISOString()
        });
        
        // Store in localStorage for persistence
        this.saveSessionToStorage();
        
        // Update session indicator
        this.updateSessionIndicator();
        
        console.log(`💾 Stored ${sender} message in session ${this.currentSessionKey}`);
    }

    saveSessionToStorage() {
        try {
            localStorage.setItem('chatbot_sessions', JSON.stringify(this.sessionHistory));
            localStorage.setItem('chatbot_current_session', this.currentSessionKey);
        } catch (error) {
            console.warn('Failed to save session to localStorage:', error);
        }
    }

    loadSessionFromStorage() {
        try {
            const sessions = localStorage.getItem('chatbot_sessions');
            const currentSession = localStorage.getItem('chatbot_current_session');
            
            if (sessions) {
                this.sessionHistory = JSON.parse(sessions);
                console.log('✅ Loaded session history from localStorage');
            }
            
            if (currentSession) {
                this.currentSessionKey = currentSession;
                console.log('✅ Restored current session:', currentSession);
                // Restore chat messages for current session
                this.restoreChatMessages();
                // Update session indicator
                this.updateSessionIndicator();
            }
        } catch (error) {
            console.warn('Failed to load session from localStorage:', error);
            this.sessionHistory = {};
            this.currentSessionKey = null;
        }
    }

    restoreChatMessages() {
        if (!this.currentSessionKey || !this.sessionHistory[this.currentSessionKey]) return;
        
        const messages = this.sessionHistory[this.currentSessionKey];
        const messagesContainer = document.getElementById('chatMessages');
        
        // Clear existing messages except welcome message
        const welcomeMessage = messagesContainer.querySelector('.welcome-message');
        messagesContainer.innerHTML = '';
        if (welcomeMessage) {
            messagesContainer.appendChild(welcomeMessage);
        }
        
        // Restore all messages for this session
        messages.forEach(msg => {
            this.addMessage(msg.sender, msg.message, false); // false = don't store again
        });
        
        // Update session indicator
        this.updateSessionIndicator();
        
        console.log(`✅ Restored ${messages.length} messages for session ${this.currentSessionKey}`);
    }

    startNewSession() {
        this.currentSessionKey = `chat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        this.sessionHistory[this.currentSessionKey] = [];
        this.saveSessionToStorage();
        
        // Clear current chat display
        const messagesContainer = document.getElementById('chatMessages');
        const welcomeMessage = messagesContainer.querySelector('.welcome-message');
        messagesContainer.innerHTML = '';
        if (welcomeMessage) {
            messagesContainer.appendChild(welcomeMessage);
        }
        
        // Update session indicator
        this.updateSessionIndicator();
        
        console.log('🆕 Started new chat session:', this.currentSessionKey);
        this.showToast('Started new chat session', 'success', 2000);
    }

    updateSessionIndicator() {
        const indicator = document.getElementById('sessionIndicator');
        if (indicator) {
            if (this.currentSessionKey) {
                const sessionTime = new Date(parseInt(this.currentSessionKey.split('_')[1])).toLocaleTimeString();
                const messageCount = this.sessionHistory[this.currentSessionKey]?.length || 0;
                indicator.textContent = `Session: ${sessionTime} (${Math.floor(messageCount/2)} exchanges)`;
            } else {
                indicator.textContent = 'Online - Ready to help with animal health';
            }
        }
    }

    async clearCurrentSession() {
        if (!this.currentSessionKey) {
            this.showToast('No active session to clear', 'info', 2000);
            return;
        }

        try {
            // Clear from server
            const response = await fetch('/api/chat/clear', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    session_key: this.currentSessionKey
                })
            });

            const data = await response.json();
            
            if (data.success) {
                // Clear from local storage
                delete this.sessionHistory[this.currentSessionKey];
                this.saveSessionToStorage();
                
                // Clear UI
                const messagesContainer = document.getElementById('chatMessages');
                const welcomeMessage = messagesContainer.querySelector('.welcome-message');
                messagesContainer.innerHTML = '';
                if (welcomeMessage) {
                    messagesContainer.appendChild(welcomeMessage);
                }
                
                // Update session indicator
                this.updateSessionIndicator();
                
                this.showToast('Chat history cleared', 'success', 2000);
                console.log('✅ Session cleared:', this.currentSessionKey);
            } else {
                this.showToast('Failed to clear chat history', 'error');
            }
        } catch (error) {
            console.error('Error clearing session:', error);
            this.showToast('Failed to clear chat history', 'error');
        }
    }

    async loadChatSessions() {
        try {
            const response = await fetch('/api/chat/sessions');
            const data = await response.json();
            
            if (data.success) {
                return data.sessions;
            } else {
                console.error('Failed to load chat sessions:', data.error);
                return [];
            }
        } catch (error) {
            console.error('Error loading chat sessions:', error);
            return [];
        }
    }

    // =================== NOTIFICATIONS ===================

    showToast(message, type = 'error', duration = 5000) {
        // Map toast types to actual toast elements
        let toastId, messageId;
        
        switch(type) {
            case 'success':
                toastId = 'successToast';
                messageId = 'successMessage';
                break;
            case 'info':
                toastId = 'successToast'; // Use success toast for info messages
                messageId = 'successMessage';
                break;
            case 'error':
            default:
                toastId = 'errorToast';
                messageId = 'errorMessage';
        }
        
        const toast = document.getElementById(toastId);
        const messageElement = document.getElementById(messageId);
        
        if (toast && messageElement) {
            messageElement.textContent = message;
            toast.style.display = 'flex';
            
            // Auto hide after duration
            setTimeout(() => {
                this.hideToast(type);
            }, duration);
        } else {
            // Fallback to console if toast elements don't exist
            console.log(`${type.toUpperCase()}: ${message}`);
        }
    }

    hideToast(type) {
        // Map toast types to actual toast elements
        let toastId;
        
        switch(type) {
            case 'success':
            case 'info':
                toastId = 'successToast';
                break;
            case 'error':
            default:
                toastId = 'errorToast';
        }
        
        const toast = document.getElementById(toastId);
        if (toast) {
            toast.style.display = 'none';
        }
    }
}

// =================== INITIALIZATION ===================

// Initialize the chatbot when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    try {
        window.veterinaryChatbot = new VeterinaryChatbot();
        // Add shorter alias for console testing
        window.chatbot = window.veterinaryChatbot;
        console.log('✅ Chatbot initialization completed successfully');
        console.log('🧪 For testing: Use chatbot.testTTS("hi") or chatbot.listVoices() in console');
    } catch (error) {
        console.error('❌ Chatbot initialization failed:', error);
        
        // Show error message to user
        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #f44336;
            color: white;
            padding: 15px;
            border-radius: 5px;
            z-index: 10000;
            max-width: 300px;
        `;
        errorDiv.innerHTML = `
            <strong>⚠️ Initialization Error</strong><br>
            Some chatbot features may not work properly.<br>
            Please refresh the page.
        `;
        document.body.appendChild(errorDiv);
        
        // Auto-remove error after 10 seconds
        setTimeout(() => {
            if (errorDiv.parentNode) {
                errorDiv.parentNode.removeChild(errorDiv);
            }
        }, 10000);
    }
});

// Handle page visibility changes for speech synthesis
document.addEventListener('visibilitychange', () => {
    try {
        if (document.hidden && window.speechSynthesis && window.speechSynthesis.speaking) {
            window.speechSynthesis.pause();
        } else if (!document.hidden && window.speechSynthesis && window.speechSynthesis.paused) {
            window.speechSynthesis.resume();
        }
    } catch (error) {
        console.warn('Speech synthesis visibility handling error:', error);
    }
});

// Handle beforeunload to cleanup speech
window.addEventListener('beforeunload', () => {
    try {
        if (window.speechSynthesis && window.speechSynthesis.speaking) {
            window.speechSynthesis.cancel();
        }
    } catch (error) {
        console.warn('Speech synthesis cleanup error:', error);
    }
});