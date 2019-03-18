.PHONY: build
build:
	python3 setup.py sdist bdist_wheel --universal

.PHONY: clean
clean:
	rm -rf dist/*
	rm -rf build/*
	rm -rf *.egg-info
	rm -rf csbootstrap/__pycache__
