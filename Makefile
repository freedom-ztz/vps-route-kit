.PHONY: test check

test:
	python3 -m unittest discover -s tests -v

check: test
	python3 scripts/check_public.py
	git diff --check
