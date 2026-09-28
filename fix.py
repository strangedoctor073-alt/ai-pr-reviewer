import sys

content = open('tests/test_orchestrator.py').read()
content = content.replace('"1 finding(s)" in body', '"Issues Flagged** | 1" in body')
content = content.replace('assert "## \\U0001f916 PR Review \\u2014 Claude" in posted["body"]', 'assert "## \\U0001f916 AI PR Review" in posted["body"]')
content = content.replace('assert first == f"## \\U0001f916 PR Review \\u2014 {label} \\u00b7 no issues found", first', 'assert "## \\U0001f916 AI PR Review" in first')
content = content.replace('assert md.splitlines()[0].endswith("\\u00b7 2 finding(s)")', 'assert "Issues Flagged** | 2" in md')
open('tests/test_orchestrator.py', 'w').write(content)
