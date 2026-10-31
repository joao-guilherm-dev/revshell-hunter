.PHONY: install test lint format demo docker clean

install:
	python -m pip install -e ".[dev]"

test:
	pytest --cov=revshell_hunter --cov-report=term-missing

lint:
	ruff check .

format:
	ruff check --fix .

demo:
	python -m revshell_hunter demo

docker:
	docker build -t revshell-hunter .

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .coverage htmlcov
