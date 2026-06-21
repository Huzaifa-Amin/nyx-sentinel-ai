# NYX SENTINEL AI — Makefile
# Common development tasks

.PHONY: install test lint demo clean help

help:          ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:       ## Install all dependencies (dev + runtime)
	pip install --upgrade pip
	pip install -r requirements-dev.txt
	pip install -e .

test:          ## Run full test suite with coverage
	pytest tests/ -v --cov=src --cov-report=term-missing --tb=short

test-fast:     ## Run tests without coverage (faster)
	pytest tests/ -v --tb=short

lint:          ## Run ruff linter
	ruff check src/ tests/ scripts/

demo:          ## Run pipeline on all sample alerts (stub mode)
	python scripts/run_pipeline.py data/sample_alerts/ --stub

demo-brute:    ## Run pipeline on brute force alert
	python scripts/run_pipeline.py data/sample_alerts/brute_force_alert.json --stub

demo-ps:       ## Run pipeline on PowerShell alert
	python scripts/run_pipeline.py data/sample_alerts/powershell_alert.json --stub

demo-recon:    ## Run pipeline on reconnaissance alert
	python scripts/run_pipeline.py data/sample_alerts/recon_alert.json --stub

clean:         ## Remove generated files and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null; true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	find . -name ".coverage" -delete 2>/dev/null; true
	rm -rf htmlcov/ coverage.xml dist/ build/ *.egg-info 2>/dev/null; true
	@echo "Clean complete."
