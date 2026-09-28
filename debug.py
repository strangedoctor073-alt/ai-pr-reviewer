from tests.test_multi_provider import *
import pytest

def test_debug():
    mp = pytest.MonkeyPatch()
    provider = OpenAIProvider(api_key='test')
    context = _mock_context([FileDiff('a.py', 'a.py')])
    def mock_post(*args, **kwargs):
        mock = Mock()
        mock.raise_for_status = Mock()
        mock.json.return_value = {
            'choices': [{
                'message': {
                    'content': '{"summary": "Looks good", "findings": []}'
                }
            }]
        }
        return mock
    mp.setattr(provider._client, 'post', mock_post)
    outcome = provider.analyze(context)
    print(outcome.warnings)

test_debug()
