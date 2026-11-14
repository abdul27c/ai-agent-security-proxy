.PHONY: install test lint format demo serve docker

install:
	pip install -e ".[dev]"

test:
	pytest --cov --cov-report=term-missing

lint:
	ruff check . && ruff format --check .

format:
	ruff format . && ruff check . --fix

demo:
	python demo.py

serve:
	uvicorn proxy.main:app --app-dir src --reload --port 8000

docker:
	docker build -t ai-agent-security-proxy .
