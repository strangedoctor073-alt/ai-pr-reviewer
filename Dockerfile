FROM python:3.12-slim

WORKDIR /app

COPY requirements-action.txt .
RUN pip install --no-cache-dir -r requirements-action.txt

COPY ai_pr_reviewer ./ai_pr_reviewer

ENV PYTHONPATH=/app
WORKDIR /github/workspace

# GitHub Actions provides INPUT_* env vars for inputs and GITHUB_EVENT_PATH
# for event context; reports are written into the mounted workspace.
ENTRYPOINT ["python", "-m", "ai_pr_reviewer"]
