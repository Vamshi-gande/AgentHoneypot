"""
Agentic Honey-Pot API for Scam Detection & Intelligence Extraction
Uses rule-based scam detection + Hugging Face Inference API for conversations
Refactored for Fly.io deployment with environment variable configuration
"""

from flask import Flask, request, jsonify
import requests
import re
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ============================================================================
# ENVIRONMENT VARIABLE CONFIGURATION - FAIL FAST IF MISSING
# ============================================================================

def get_required_env(var_name: str) -> str:
    """Get required environment variable or fail with clear error"""
    value = os.environ.get(var_name)
    if not value:
        error_msg = f"FATAL: Required environment variable '{var_name}' is not set"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    return value

# Load and validate all required environment variables at startup
try:
    API_KEY = get_required_env('API_KEY')
    HF_API_TOKEN = get_required_env('HF_API_TOKEN')
    HF_MODEL_ID = os.environ.get('HF_MODEL_ID', 'mistralai/Mistral-7B-Instruct-v0.2')
    GUVI_CALLBACK_URL = get_required_env('GUVI_CALLBACK_URL')
    
    logger.info("✓ All required environment variables loaded successfully")
    logger.info(f"✓ Using Hugging Face model: {HF_MODEL_ID}")
except RuntimeError as e:
    logger.error("=" * 80)
    logger.error("STARTUP FAILURE - Missing Required Environment Variables")
    logger.error("=" * 80)
    logger.error("Please set the following environment variables:")
    logger.error("  - API_KEY: Request authentication key")
    logger.error("  - HF_API_TOKEN: Hugging Face API token")
    logger.error("  - HF_MODEL_ID: (optional) Hugging Face model ID")
    logger.error("  - GUVI_CALLBACK_URL: Callback endpoint URL")
    logger.error("=" * 80)
    raise

# Hugging Face Inference API configuration
HF_API_URL = "https://api-inference.huggingface.co/v1/chat/completions"

# Session storage (in-memory is acceptable for Fly.io deployment)
sessions = {}

class ScamDetector:
    """Rule-based scam detection system"""
    
    def __init__(self):
        self.scam_patterns = {
            'bank_fraud': [
                r'bank account.*block',
                r'account.*suspend',
                r'verify.*account',
                r'update.*kyc',
                r'card.*expir',
                r'unauthorized.*transaction',
                r'account.*deactivat'
            ],
            'upi_fraud': [
                r'upi.*id',
                r'paytm.*wallet',
                r'google.*pay',
                r'phonepe',
                r'refund.*pending',
                r'payment.*fail'
            ],
            'phishing': [
                r'click.*link',
                r'verify.*here',
                r'confirm.*identity',
                r'reset.*password',
                r'http[s]?://(?!.*\.gov|.*\.bank)',
                r'bit\.ly',
                r'tinyurl'
            ],
            'urgency_tactics': [
                r'immediately',
                r'urgent',
                r'within.*hours',
                r'expire.*today',
                r'last.*chance',
                r'act now',
                r'limited.*time'
            ],
            'fake_lottery': [
                r'won.*prize',
                r'lottery.*winner',
                r'congratulations.*selected',
                r'claim.*reward'
            ],
            'impersonation': [
                r'tax.*department',
                r'income.*tax',
                r'police.*station',
                r'cyber.*cell',
                r'rbi.*official',
                r'government.*officer'
            ]
        }
        
        self.suspicious_keywords = [
            'urgent', 'verify', 'confirm', 'suspend', 'block', 'expire',
            'immediately', 'click here', 'account', 'password', 'otp',
            'cvv', 'pin', 'card number', 'bank details', 'refund'
        ]
    
    def detect_scam(self, text: str) -> Tuple[bool, List[str], float]:
        """
        Detect if message is a scam
        Returns: (is_scam, detected_categories, confidence_score)
        """
        text_lower = text.lower()
        detected_categories = []
        total_matches = 0
        
        for category, patterns in self.scam_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    if category not in detected_categories:
                        detected_categories.append(category)
                    total_matches += 1
        
        # Calculate confidence score
        confidence = min(total_matches * 0.15, 1.0)
        
        # Additional indicators
        has_link = bool(re.search(r'http[s]?://', text))
        has_phone = bool(re.search(r'\+?[0-9]{10,}', text))
        keyword_count = sum(1 for kw in self.suspicious_keywords if kw in text_lower)
        
        if has_link:
            confidence += 0.2
        if has_phone and any(cat in detected_categories for cat in ['bank_fraud', 'upi_fraud']):
            confidence += 0.15
        if keyword_count >= 3:
            confidence += 0.1
        
        confidence = min(confidence, 1.0)
        is_scam = confidence >= 0.3 or len(detected_categories) >= 2
        
        return is_scam, detected_categories, confidence


class IntelligenceExtractor:
    """Extract scam-related intelligence from conversations"""
    
    @staticmethod
    def extract(conversation_history: List[Dict]) -> Dict:
        """Extract intelligence from conversation"""
        all_text = " ".join([msg['text'] for msg in conversation_history])
        
        intelligence = {
            'bankAccounts': [],
            'upiIds': [],
            'phishingLinks': [],
            'phoneNumbers': [],
            'suspiciousKeywords': []
        }
        
        # Extract bank accounts
        bank_patterns = [
            r'\b\d{9,18}\b',  # Account numbers
            r'\b[A-Z]{4}0[A-Z0-9]{6}\b'  # IFSC codes
        ]
        for pattern in bank_patterns:
            matches = re.findall(pattern, all_text)
            intelligence['bankAccounts'].extend(matches)
        
        # Extract UPI IDs
        upi_pattern = r'\b[\w\.-]+@[\w\.-]+\b'
        upi_matches = re.findall(upi_pattern, all_text)
        intelligence['upiIds'].extend([u for u in upi_matches if any(
            provider in u.lower() for provider in ['paytm', 'okaxis', 'ybl', 'axisbank', 'sbi', 'oksbi']
        )])
        
        # Extract links
        link_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        intelligence['phishingLinks'].extend(re.findall(link_pattern, all_text))
        
        # Extract phone numbers
        phone_pattern = r'\+?[0-9]{10,13}'
        intelligence['phoneNumbers'].extend(re.findall(phone_pattern, all_text))
        
        # Extract suspicious keywords
        suspicious_kw = [
            'urgent', 'verify', 'immediately', 'block', 'suspend',
            'otp', 'cvv', 'pin', 'password', 'account number'
        ]
        for kw in suspicious_kw:
            if kw in all_text.lower():
                intelligence['suspiciousKeywords'].append(kw)
        
        # Remove duplicates
        for key in intelligence:
            intelligence[key] = list(set(intelligence[key]))
        
        return intelligence


class PersonaManager:
    """Manage different personas for the AI agent"""
    
    PERSONAS = {
        'confused_elderly': {
            'description': 'Elderly person, not tech-savvy, asks basic questions',
            'traits': [
                'Uses simple language',
                'Confused about technology',
                'Asks for clarification frequently',
                'Mentions grandchildren or family',
                'Slow to understand technical terms'
            ]
        },
        'cautious_professional': {
            'description': 'Working professional, somewhat tech-savvy but cautious',
            'traits': [
                'Asks verification questions',
                'Wants to confirm through official channels',
                'Mentions workplace or busy schedule',
                'Seeks documentation',
                'Concerned about security'
            ]
        },
        'eager_youth': {
            'description': 'Young person, excited but inexperienced',
            'traits': [
                'Uses casual language',
                'Excited about opportunities',
                'Asks about quick solutions',
                'Mentions social media or trends',
                'Impatient but compliant'
            ]
        },
        'skeptical_adult': {
            'description': 'Middle-aged person, somewhat aware of scams',
            'traits': [
                'Asks probing questions',
                'Mentions past experiences',
                'Expresses initial doubt',
                'Eventually becomes convinced',
                'Seeks guarantees'
            ]
        }
    }
    
    @staticmethod
    def select_persona(scam_categories: List[str], conversation_history: List[Dict]) -> str:
        """Select appropriate persona based on scam type"""
        if 'impersonation' in scam_categories or 'bank_fraud' in scam_categories:
            return 'confused_elderly'
        elif 'upi_fraud' in scam_categories:
            return 'cautious_professional'
        elif 'fake_lottery' in scam_categories:
            return 'eager_youth'
        else:
            return 'skeptical_adult'
    
    @staticmethod
    def get_system_prompt(persona: str) -> str:
        """Get system prompt for the selected persona"""
        persona_data = PersonaManager.PERSONAS.get(persona, PersonaManager.PERSONAS['skeptical_adult'])
        
        traits_str = '\n'.join([f"- {trait}" for trait in persona_data['traits']])
        
        system_prompt = f"""You are roleplaying as a potential scam victim with the following persona:

{persona_data['description']}

Key behavioral traits:
{traits_str}

IMPORTANT INSTRUCTIONS:
- Stay completely in character at all times
- Never break the fourth wall or acknowledge you're an AI
- Your goal is to engage the scammer and extract information
- Ask clarifying questions that fit your persona
- Show appropriate emotions (confusion, excitement, concern)
- Gradually become more trusting to keep them engaged
- Ask for specific details (account numbers, links, phone numbers)
- Keep responses conversational and natural (2-3 sentences max)
- Never reveal you know this is a scam

Remember: You are helping gather intelligence about scammers to protect others."""
        
        return system_prompt


class HuggingFaceConversationAgent:
    """
    AI conversation agent using Hugging Face Inference API
    Replaces Ollama with HF API calls
    """
    
    def __init__(self):
        self.naive_responses = [
            "I'm not sure I understand. Can you explain more?",
            "This sounds interesting. What do I need to do?",
            "Oh my! Is this urgent? What should I do?",
            "I want to help, but I'm confused. Can you guide me?",
            "Should I share my details with you directly?"
        ]
    
    def call_huggingface_api(self, prompt: str, temperature: float = 0.7, max_tokens: int = 150) -> Optional[str]:
        """
        Call Hugging Face Inference API with defensive response parsing
        """
        try:
            headers = {
                "Authorization": f"Bearer {HF_API_TOKEN}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": HF_MODEL_ID,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            logger.info("Calling Hugging Face Inference API...")
            
            response = requests.post(
                HF_API_URL,
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Defensive parsing: HF API typically returns a list
                try:
                    content = result["choices"][0]["message"]["content"]
                    logger.info(f"✓ HF API response received: {len(content)} chars")
                    return content.strip()
                except (KeyError, IndexError, TypeError) as e:
                    logger.error(f"Failed to parse HF chat response: {result}")
                    return None
                    
            elif response.status_code == 503:
                logger.warning("HF model is loading, this may take a moment...")
                return None
            
            else:
                logger.error(f"HF API error {response.status_code}: {response.text}")
                return None
        
        except requests.exceptions.Timeout:
            logger.error("HF API request timed out")
            return None
        except Exception as e:
            logger.error(f"Error calling HF API: {e}", exc_info=True)
            return None
    
    def generate_response(self, session_data: Dict) -> str:
        """
        Generate contextual response based on conversation history and persona
        """
        conversation_history = session_data['conversationHistory']
        persona = session_data.get('persona', 'skeptical_adult')
        
        # Use naive responses for first 2 exchanges to build rapport
        if len(conversation_history) <= 2:
            import random
            return random.choice(self.naive_responses)
        
        # Build conversation context
        recent_messages = conversation_history[-6:]  # Last 3 exchanges
        context = "\n".join([
            f"{'Scammer' if msg['sender'] == 'scammer' else 'You'}: {msg['text']}"
            for msg in recent_messages
        ])
        
        # Get system prompt for persona
        system_prompt = PersonaManager.get_system_prompt(persona)
        
        # Construct full prompt for HF model
        full_prompt = f"""{system_prompt}

Conversation so far:
{context}

Based on the above conversation, respond in character as the victim. Keep your response short (2-3 sentences), natural, and in character. Do not include any labels like "You:" or "Victim:" - just write the response text directly.

Response:"""
        
        # Call Hugging Face API
        response = self.call_huggingface_api(
            prompt=full_prompt,
            temperature=0.7,
            max_tokens=150
        )
        
        # Fallback to naive response if API fails or returns empty
        if not response or len(response.strip()) == 0:
            logger.warning("HF API returned empty/null, using fallback response")
            import random
            return random.choice(self.naive_responses)
        
        # Clean up response (remove any accidental labels)
        response = response.strip()
        for prefix in ["You:", "Victim:", "Response:", "User:"]:
            if response.startswith(prefix):
                response = response[len(prefix):].strip()
        
        # Limit response length for natural conversation
        if len(response) > 300:
            sentences = response.split('.')
            response = '. '.join(sentences[:2]) + '.'
        
        return response


# Initialize components
scam_detector = ScamDetector()
intelligence_extractor = IntelligenceExtractor()
conversation_agent = HuggingFaceConversationAgent()


def validate_request_body(data: dict) -> Tuple[bool, Optional[str]]:
    """Validate the request body structure"""
    
    if not isinstance(data, dict):
        return False, "Request body must be a JSON object"
    
    # Check required fields
    required_fields = ['sessionId', 'message']
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"
    
    # Validate sessionId
    if not isinstance(data['sessionId'], str) or not data['sessionId'].strip():
        return False, "sessionId must be a non-empty string"
    
    # Validate message structure
    message = data['message']
    if not isinstance(message, dict):
        return False, "message must be an object"
    
    message_required = ['sender', 'text', 'timestamp']
    for field in message_required:
        if field not in message:
            return False, f"message is missing required field: {field}"
    
    if message['sender'] != 'scammer':
        return False, "message.sender must be 'scammer'"
    
    if not isinstance(message['text'], str) or not message['text'].strip():
        return False, "message.text must be a non-empty string"
    
    if not isinstance(message['timestamp'], int) or message['timestamp'] <= 0:
        return False, "message.timestamp must be a positive integer"
    
    # Validate optional fields if present
    if 'conversationHistory' in data:
        if not isinstance(data['conversationHistory'], list):
            return False, "conversationHistory must be an array"
    
    if 'metadata' in data:
        if not isinstance(data['metadata'], dict):
            return False, "metadata must be an object"
    
    return True, None


@app.route('/honeypot', methods=['POST'])
def honeypot_endpoint():
    """Main honeypot API endpoint"""
    
    # Check Content-Type header
    content_type = request.headers.get('Content-Type', '')
    if 'application/json' not in content_type:
        logger.warning(f"Invalid Content-Type: {content_type}")
        return jsonify({"error": "INVALID_REQUEST_BODY", "message": "Content-Type must be application/json"}), 400
    
    # Verify API key
    api_key = request.headers.get('x-api-key')
    if api_key != API_KEY:
        logger.warning(f"Unauthorized access attempt with key: {api_key}")
        return jsonify({"error": "Unauthorized"}), 401
    
    # Parse and validate request body
    try:
        data = request.get_json(force=True)
    except Exception as e:
        logger.error(f"Failed to parse JSON: {e}")
        return jsonify({"error": "INVALID_REQUEST_BODY", "message": "Invalid JSON format"}), 400
    
    # Validate request structure
    is_valid, error_message = validate_request_body(data)
    if not is_valid:
        logger.warning(f"Invalid request body: {error_message}")
        return jsonify({"error": "INVALID_REQUEST_BODY", "message": error_message}), 400
    
    try:
        session_id = data.get('sessionId')
        message = data.get('message')
        conversation_history = data.get('conversationHistory', [])
        metadata = data.get('metadata', {})
        
        # Initialize or retrieve session
        if session_id not in sessions:
            sessions[session_id] = {
                'sessionId': session_id,
                'conversationHistory': [],
                'scamDetected': False,
                'scamCategories': [],
                'confidence': 0.0,
                'persona': None,
                'intelligenceExtracted': False,
                'metadata': metadata
            }
        
        session_data = sessions[session_id]
        
        # Add current message to history
        session_data['conversationHistory'].append(message)
        
        # Scam detection runs exactly ONCE per session (on first message)
        if len(session_data['conversationHistory']) == 1:
            is_scam, categories, confidence = scam_detector.detect_scam(message['text'])
            
            session_data['scamDetected'] = is_scam
            session_data['scamCategories'] = categories
            session_data['confidence'] = confidence
            
            if is_scam:
                # Select persona based on detected categories
                persona = PersonaManager.select_persona(categories, session_data['conversationHistory'])
                session_data['persona'] = persona
                logger.info(f"Scam detected! Session: {session_id}, Categories: {categories}, Confidence: {confidence:.2f}, Persona: {persona}")
        
        # Generate response
        if session_data['scamDetected']:
            reply = conversation_agent.generate_response(session_data)
            
            # Add agent response to history
            agent_message = {
                'sender': 'user',
                'text': reply,
                'timestamp': int(datetime.now().timestamp() * 1000)
            }
            session_data['conversationHistory'].append(agent_message)
            
            # Early-extraction trigger: extract and callback when conditions are met
            if not session_data['intelligenceExtracted']:
                total_messages = len(session_data['conversationHistory'])

                # Run extraction to check for actionable IOCs
                intelligence = intelligence_extractor.extract(session_data['conversationHistory'])

                has_actionable_ioc = (
                    len(intelligence['upiIds']) > 0
                    or len(intelligence['phishingLinks']) > 0
                    or len(intelligence['phoneNumbers']) > 0
                )

                should_send = (
                    total_messages >= 8                          # enough back-and-forth
                    or session_data['confidence'] >= 0.7         # high-confidence scam
                    or has_actionable_ioc                        # concrete IOC extracted
                )

                if should_send:
                    send_final_result(session_id, session_data)
                    session_data['intelligenceExtracted'] = True
            
            # Return response with exact required schema
            return jsonify({
                "sessionId": session_id,
                "status": "success",
                "message": agent_message
            }), 200
        else:
            # Non-scam branch: return same schema structure
            fallback_message = {
                "sender": "user",
                "text": "I'm sorry, I don't understand. Can you please clarify?",
                "timestamp": int(datetime.now().timestamp() * 1000)
            }
            return jsonify({
                "sessionId": session_id,
                "status": "success",
                "message": fallback_message
            }), 200
    
    except Exception as e:
        logger.error(f"Error processing request: {e}", exc_info=True)
        return jsonify({"error": "Internal server error", "message": str(e)}), 500


def send_final_result(session_id: str, session_data: Dict):
    """Send final intelligence to GUVI callback endpoint"""
    
    try:
        # Extract intelligence
        intelligence = intelligence_extractor.extract(session_data['conversationHistory'])
        
        # Build agent notes
        categories_str = ', '.join(session_data['scamCategories'])
        persona_str = session_data.get('persona', 'unknown')
        agent_notes = f"Scam type: {categories_str}. Used {persona_str} persona. " \
                     f"Confidence: {session_data['confidence']:.2f}. " \
                     f"Successfully engaged scammer in multi-turn conversation."
        
        payload = {
            "sessionId": session_id,
            "scamDetected": session_data['scamDetected'],
            "totalMessagesExchanged": len(session_data['conversationHistory']),
            "extractedIntelligence": intelligence,
            "agentNotes": agent_notes
        }
        
        logger.info(f"Sending final result to GUVI for session {session_id}")
        
        # Send to GUVI endpoint
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info(f"Successfully sent final result for session {session_id}")
        else:
            logger.error(f"Failed to send final result: {response.status_code} - {response.text}")
    
    except Exception as e:
        logger.error(f"Error sending final result: {e}", exc_info=True)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()}), 200


@app.route('/sessions/<session_id>', methods=['GET'])
def get_session(session_id: str):
    """Get session details (for debugging)"""
    if session_id in sessions:
        return jsonify(sessions[session_id]), 200
    return jsonify({"error": "Session not found"}), 404


if __name__ == '__main__':
    logger.info("=" * 80)
    logger.info("Starting Agentic Honey-Pot API Server with Hugging Face Integration")
    logger.info("=" * 80)
    logger.info(f"✓ Model: {HF_MODEL_ID}")
    logger.info(f"✓ API Key: {API_KEY[:10]}...")
    logger.info(f"✓ Callback URL: {GUVI_CALLBACK_URL}")
    logger.info("=" * 80)
    port = int(os.environ.get("PORT", 7860))
    app.run(host="0.0.0.0", port=port)

