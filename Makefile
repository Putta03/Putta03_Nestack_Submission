.PHONY: venv install install-dev test run admin

venv:
	python3 -m venv .venv

install: venv
	.venv/bin/pip install -r requirements.txt

install-dev: venv
	.venv/bin/pip install -r requirements-dev.txt

test:
	.venv/bin/pytest

run:
	.venv/bin/uvicorn app.asgi:app --host 127.0.0.1 --port 8000 --no-server-header

admin:
	.venv/bin/python scripts/promote_admin.py $(USERNAME)
