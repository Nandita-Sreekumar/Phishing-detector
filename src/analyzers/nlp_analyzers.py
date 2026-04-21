import json
import logging
import ollama 

from src.config import settings
from src.models.responses import ContentAnalysis

logger = logging.getLogger(__name__)


class NLPAnalyzer:

    """Analyzes text content using local LLMs via Ollama."""
    def __init__(self):
        """Initialize NLP analyzer with Ollama model client."""
        self.model = settings.ollama_model

    async def analyze_content(self, email_text: str) -> ContentAnalysis:
        prompt = f"""You are a cybersecurity phishing detection system. Analyze the following email for phishing indicators. 
        You MUST respond in valid JSON only, no other text.
        Evaluate these dimensions on a 0.0 to 1.0 scale:
        - urgency_score: How much urgency/time pressure does the email create?
        - authority_impersonation: Does it impersonate authority (CEO, IT, bank, gov)?
        - action_pressure: Does it pressure immediate action (click, verify, respond)?
        - reward_bait: Does it offer rewards, refunds, prizes, or bonuses?
        - threat_language: Does it threaten negative consequences (suspension, legal)?
        - grammar_consistency: How consistent is the writing quality? (0=very inconsistent=likely AI, 1=natural)
        - personal_info_request: Does it request sensitive info (passwords, SSN, CC)?
        - ai_generated_probability: Overall probability this email was AI-generated (0.0-1.0)
        - social_engineering_tactics: List of specific tactics identified (array of strings)
        - reasoning: Brief explanation of your analysis (string)
        Respond ONLY with a JSON object matching this schema.
        Analyze this email:{email_text}
        """
        try:
            response = ollama.chat(model=self.model, messages=[
                {'role': 'user', 'content': prompt}
            ])
            
            # In a real build, you would parse the JSON from response['message']['content']
            # to populate the ContentAnalysis model.
            response_text = response['message']['content']
            analysis_data = json.loads(response_text)
            return ContentAnalysis(**analysis_data)
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Ollama response as JSON: {e}")
            logger.error(f"Response text: {response_text}")
            # Return default analysis on error
            return self._default_analysis()
        
        except Exception as e:
            logger.error(f"Error in NLP analysis: {e}")
            return self._default_analysis()

    def _default_analysis(self) -> ContentAnalysis:
        """Return default analysis"""
        return ContentAnalysis(
            urgency_score=0.0,
            authority_impersonation=0.0,
            action_pressure=0.0,
            reward_bait=0.0,
            threat_language=0.0,
            grammar_consistency=0.5,
            personal_info_request=0.0,
            ai_generated_probability=0.0,
            social_engineering_tactics=[],
            reasoning="Analysis unavailable - using default values"
        )