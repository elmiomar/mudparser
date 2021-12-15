# Installation

## Requirements

- Python 3.10 or higher
- pip (Python package installer)

## Basic Installation

Install MudParser from PyPI:

```bash
pip install mudparser
```

## Installation with Extras

MudParser provides optional dependencies for additional features:

### Demo Application (Streamlit)

```bash
pip install mudparser[demo]
```

### Development Dependencies

```bash
pip install mudparser[dev]
```

### Documentation Building

```bash
pip install mudparser[docs]
```

### All Features

```bash
pip install mudparser[all]
```

## Development Installation

For development, clone the repository and install in editable mode:

```bash
# Clone the repository
git clone https://github.com/elmiomar/mudparser.git
cd mudparser

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Verifying Installation

After installation, verify it works:

```bash
# Check CLI is available
mudparser --version

# Or in Python
python -c "import mudparser; print(mudparser.__version__)"
```

## Dependencies

MudParser depends on the following packages:

| Package | Version | Purpose |
|---------|---------|---------|
| pydantic | >=2.0 | Data validation and models |
| pyyaml | >=6.0 | YAML export |
| rich | >=13.0 | CLI output formatting |
| typer | >=0.9 | CLI framework |
| httpx | >=0.25 | HTTP client for URL fetching |

Optional dependencies:

| Package | Extra | Purpose |
|---------|-------|---------|
| streamlit | demo | Web demo application |
| pytest | dev | Testing |
| mypy | dev | Type checking |
| ruff | dev | Linting |
| mkdocs-material | docs | Documentation |

## Platform Support

MudParser is tested on:

- Linux (Ubuntu, Debian, CentOS)
- macOS (10.15+)
- Windows (10, 11)

## Troubleshooting

### ImportError: No module named 'mudparser'

Ensure you're using the correct Python environment:

```bash
which python
pip list | grep mudparser
```

### Permission Denied on Installation

Use `--user` flag or a virtual environment:

```bash
pip install --user mudparser
```

### Outdated pip

Update pip before installing:

```bash
pip install --upgrade pip
pip install mudparser
```
