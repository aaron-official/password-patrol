# Contributing to Password Patrol

## Getting Started

1.  Clone the repository.
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    pip install -r requirements-dev.txt
    ```
3.  Run tests:
    ```bash
    pytest
    ```

## Code Style

-   We use **Ruff** for linting and formatting.
-   We use **mypy** for static type checking.

Run checks before pushing:
```bash
ruff check .
mypy .
```

## Pull Requests

1.  Ensure all tests pass.
2.  Add tests for new features.
3.  Update documentation if needed.
