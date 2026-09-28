from unittest.mock import Mock
import pytest
import httpx
from ai_pr_reviewer.ai.openai import OpenAIProvider
from ai_pr_reviewer.ai.gemini import GeminiProvider
from ai_pr_reviewer.ai.claude import ClaudeProvider
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.context import ReviewContext
from ai_pr_reviewer.diff_parser import FileDiff
from ai_pr_reviewer.model_router import get_provider, StaticProvider
from ai_pr_reviewer.models import Finding, calculate_health_score

def _mock_context(files=None):
    ctx = Mock(spec=ReviewContext)
    ctx.files = files or []
    ctx.focus_areas = []
    ctx.project_rules = None
    return ctx

def test_openai_provider_clean_response(monkeypatch):
    provider = OpenAIProvider(api_key="test", model="gpt-test")
    context = _mock_context([FileDiff("a.py", "a.py")])
    
    def mock_post(*args, **kwargs):
        mock = Mock()
        mock.status_code = 200
        mock.raise_for_status = Mock()
        mock.json.return_value = {
            "choices": [{
                "message": {
                    "content": '{"summary": "Looks good", "findings": []}'
                }
            }]
        }
        return mock
        
    monkeypatch.setattr(provider._client, "post", mock_post)
    outcome = provider.analyze(context)
    
    assert outcome.warnings == []
    assert outcome.summary == "Looks good"
    assert outcome.findings == []
    assert outcome.model == "gpt-test"
    assert outcome.engine == "openai"

def test_openai_provider_fallback(monkeypatch):
    provider = OpenAIProvider(api_key="test", model="gpt-test")
    context = _mock_context([FileDiff("a.py", "a.py")])
    
    def mock_post(*args, **kwargs):
        resp_mock = Mock()
        resp_mock.status_code = 429
        raise httpx.HTTPStatusError("429 Too Many Requests", request=Mock(), response=resp_mock)
        
    monkeypatch.setattr(provider._client, "post", mock_post)
    outcome = provider.analyze(context)
    
    assert outcome.engine == "static"
    assert outcome.fallback_used is True

def test_gemini_provider_clean_response(monkeypatch):
    provider = GeminiProvider(api_key="test", model="gemini-test")
    context = _mock_context([FileDiff("a.py", "a.py")])
    
    def mock_post(*args, **kwargs):
        mock = Mock()
        mock.status_code = 200
        mock.raise_for_status = Mock()
        mock.json.return_value = {
            "candidates": [{
                "content": {
                    "parts": [{"text": '{"summary": "LGTM", "findings": []}'}]
                }
            }]
        }
        return mock
        
    monkeypatch.setattr(provider._client, "post", mock_post)
    outcome = provider.analyze(context)
    
    assert outcome.summary == "LGTM"
    assert outcome.findings == []
    assert outcome.model == "gemini-test"
    assert outcome.engine == "gemini"

def test_gemini_provider_fallback(monkeypatch):
    provider = GeminiProvider(api_key="test", model="gemini-test")
    context = _mock_context([FileDiff("a.py", "a.py")])
    
    def mock_post(*args, **kwargs):
        resp_mock = Mock()
        resp_mock.status_code = 500
        raise httpx.HTTPStatusError("500 Internal Server Error", request=Mock(), response=resp_mock)
        
    monkeypatch.setattr(provider._client, "post", mock_post)
    outcome = provider.analyze(context)
    
    assert outcome.engine == "static"
    assert outcome.fallback_used is True

def test_model_router_openai():
    cfg = Config(model="gpt-4o-mini", openai_api_key="test")
    provider = get_provider(cfg, _mock_context())
    assert isinstance(provider, OpenAIProvider)

def test_model_router_gemini():
    cfg = Config(model="gemini-2.0-flash", gemini_api_key="test")
    provider = get_provider(cfg, _mock_context())
    assert isinstance(provider, GeminiProvider)

def test_model_router_claude():
    cfg = Config(model="claude-sonnet-4-6", anthropic_api_key="test")
    provider = get_provider(cfg, _mock_context())
    assert isinstance(provider, ClaudeProvider)

def test_model_router_mock():
    cfg = Config(mock=True, anthropic_api_key="test")
    provider = get_provider(cfg, _mock_context())
    assert isinstance(provider, StaticProvider)

def test_calculate_health_score_clean():
    score, grade = calculate_health_score([])
    assert score == 100
    assert grade == "A+"

def test_calculate_health_score_critical():
    findings = [Finding(file="a.py", line=1, severity="critical")]
    score, grade = calculate_health_score(findings)
    assert score == 65
    assert grade == "C"

def test_calculate_health_score_high():
    findings = [Finding(file="a.py", line=1, severity="high")]
    score, grade = calculate_health_score(findings)
    assert score == 80
    assert grade == "A"
