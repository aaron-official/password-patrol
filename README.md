# Password Patrol

**Password Patrol** is a fast, modern, and secure password analysis tool. It checks your passwords for strength and known breaches using HaveIBeenPwned, providing detailed feedback and recommendations—all from a user-friendly command-line interface.

## Features
- K-anonymity breach checking (HaveIBeenPwned API)
- Local password strength analysis (8 checks)
- Batch and interactive CLI modes
- Color-coded, detailed output
- Async/await for fast batch processing
- Logging and robust error handling

## Usage

```sh
# Single password check
python cli.py "mypassword123"

# Secure interactive mode
python cli.py -i

# Batch file processing
python cli.py -f passwords.txt

# Multiple passwords with details
python cli.py -b "pwd1" "pwd2" "pwd3" --detailed
```

## Setup

1. Clone the repo:
   ```sh
   git clone https://github.com/aaron-official/password-patrol.git
   cd password-patrol
   ```
2. Create a virtual environment and activate it:
   ```sh
   python -m venv .venv
   .venv\Scripts\activate  # On Windows
   # Or: source .venv/bin/activate  # On Linux/Mac
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## License
MIT

---

**Project Highlights:**
- Async/await, dataclasses, enums, context managers
- Security best practices (K-anonymity, memory clearing)
- CLI/UX, error handling, and code organization
