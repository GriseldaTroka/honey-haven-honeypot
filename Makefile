SHELL := /bin/sh

.PHONY: help dev up down restart logs test lint makemigrations migrate shell collectstatic check clean reset backup docker-build docker-up docker-down prod-up prod-down

help:
	@echo "Available targets:"
	@echo "  dev              Start local dev server"
	@echo "  up               Start Docker Compose stack"
	@echo "  down             Stop Docker Compose stack"
	@echo "  restart          Restart Docker Compose stack"
	@echo "  logs             Follow application logs"
	@echo "  test             Run Django tests"
	@echo "  lint             Run formatting/lint checks"
	@echo "  makemigrations   Create Django migrations"
	@echo "  migrate          Apply Django migrations"
	@echo "  shell            Open Django shell"
	@echo "  collectstatic    Collect static files"
	@echo "  check            Run Django system checks"
	@echo "  clean            Remove Python caches and temp files"
	@echo "  reset            Reset local DB and re-run migrations"
	@echo "  backup           Create a backup archive"
	@echo "  docker-build     Build Docker images"
	@echo "  docker-up        Start default Docker Compose stack"
	@echo "  docker-down      Stop Docker Compose stack"
	@echo "  prod-up          Start production compose example"
	@echo "  prod-down        Stop production compose example"

# Local development uses the Django dev server.
dev:
	python manage.py runserver 0.0.0.0:8000

up docker-up:
	docker compose up -d --build --profile observability --profile honeypots

down docker-down:
	docker compose down

restart:
	docker compose down
	docker compose up -d --build --profile observability --profile honeypots

logs:
	python manage.py shell -c "from pathlib import Path; p = Path('logs/honey-web.log'); print(p.read_text()[-6000:] if p.exists() else 'No log file found')"

test:
	python manage.py test

lint:
	python -m compileall .
	python manage.py check

makemigrations:
	python manage.py makemigrations

migrate:
	python manage.py migrate

shell:
	python manage.py shell

collectstatic:
	python manage.py collectstatic --noinput

check:
	python manage.py check

clean:
	python -c "from pathlib import Path; import shutil; [shutil.rmtree(p, ignore_errors=True) for p in [Path('__pycache__'), Path('store/__pycache__'), Path('honeytrap/__pycache__'), Path('tests/__pycache__')]]"
	python -c "from pathlib import Path; [p.unlink() for p in Path('.').glob('**/*.pyc')]"

reset:
	python manage.py flush --noinput
	python manage.py migrate

backup:
	python scripts/backup_project.py

docker-build:
	docker compose build

prod-up:
	docker compose -f deploy/docker-compose.prod.yml up -d --build

prod-down:
	docker compose -f deploy/docker-compose.prod.yml down
