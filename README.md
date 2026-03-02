# 🛡️ Password Patrol

**The "Reality-First" Privacy-Preserving Password Auditor.**  
*Instantly validate password strength and check against billions of leaked credentials using K-Anonymity architecture—your secrets never leave your machine.*

---

## 🚀 Why Password Patrol?

Most password checkers ask you to trust them. We don't.
**Password Patrol** is built on a "Local-First" philosophy. It brings the auditing logic *to* your data, rather than sending your data to the cloud. By leveraging the **K-Anonymity** property of SHA-1, we can query the *HaveIBeenPwned* database of over **11 billion** breached accounts without ever revealing your actual password or even its full hash.

### Key Capabilities
- **Zero-Knowledge Breach Detection**: Your password never leaves your device. Only a 5-character hash prefix is sent to the API.
- **Local Strength Engine**: Runs 8 distinct regex-based analysis checks locally (Entropy, Patterns, Repetition).
- **Async Batch Processing**: Audit hundreds of passwords in seconds using non-blocking I/O.
- **Production-Ready**: Built-in rate limiting, exponential backoff, and robust error handling.

---

## 🏗️ Architecture & Privacy Patterns

This project follows a strict functional separation of concerns to ensure privacy.

### The "Reality-First" Data Flow
1. **Input**: User securely enters password (e.g., `mypassword`).
2. **Local Hashing**: The `checker.py` module computes the SHA-1 hash locally.
   - *Example Hash*: `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
3. **Prefix Extraction**: Splits into `Prefix` (`5BAA6`) and `Suffix` (`1E4C9...`).
4. **Anonymized Query**: Sends GET request to `api.pwnedpasswords.com/range/5BAA6`.
5. **Local Verification**: The API returns ~500-1000 suffixes that share that prefix. Your client scans this list locally for the matching suffix.
6. **Verdict**: Combines breach data with local strength analysis.

### System Components

| File | Component | Role & Responsibility |
| :--- | :--- | :--- |
| **`cli.py`** | **The Gatekeeper** | Handles user input streams, argument parsing, and formatting output. Ensures passwords are read securely (`getpass`) or via file streams to avoid shell history logging. |
| **`checker.py`** | **The Engine** | Contains the core business logic. Manages the `aiohttp` session, enforces rate limits (semaphores), and runs local regex checks. |
| **`models.py`** | **The Contract** | Defines the immutable data structures (`PasswordAnalysis`) and Security Level enums (`CRITICAL`, `WEAK`, etc.) used throughout the app. |
| **`utils.py`** | **The Support** | Helper functions for secure file reading and string manipulation. |

---

## ⚡ Quick Start

### Prerequisites
- **Python 3.8+**
- **Internet Connection** (required for the HIBP API lookup)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/aaron-official/password-patrol.git
cd password-patrol

# 2. Create Virtual Environment (Recommended)
python -m venv .venv

# 3. Activate Environment
# Windows:
.venv\Scripts\activate
# Mac/Linux:
# source .venv/bin/activate

# 4. Install Dependencies
pip install -r requirements.txt
```

## 🐳 Docker Usage (Zero Install)

Run the tool without installing Python or dependencies on your host machine.

### Build the Image
```bash
docker-compose build
```

### Run Commands
```bash
# Interactive mode
docker-compose run --rm app --interactive

# Check specific passwords
docker-compose run --rm app "password123"

# Check a file (volume mapped)
docker-compose run --rm app --file passwords.txt
```

---

## 💻 Usage Scenarios

### 1. The "Paranoid" Check (Interactive Mode)
*Best for checking your real, sensitive passwords.*
- uses `getpass` to hide input.
- Input history is never saved.

```bash
python cli.py --interactive
# Output: Enter password to check (hidden):
```

### 2. High-Volume Audit (Batch Mode)
*Best for security researchers or cleaning up legacy wordlists.*
- Reads from a file one line at a time.
- Uses async concurrency (default 5 workers) to process lists fast.

```bash
python cli.py --file old_passwords.txt --detailed
```

### 3. Quick Command Line Check
*Useful for testing dummy passwords or checking common phrases.*

```bash
python cli.py "password123" "admin" "iloveyou"
```

---

## ⚙️ Advanced Configuration

You can fine-tune the behavior of the checker using CLI flags.

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--detailed` | Show specific recommendations (e.g., "Add special chars"). | `False` |
| `--timeout` | Max seconds to wait for API response per batch. | `10` |
| `--retries` | Max retry attempts for failed API calls. | `3` |
| `--quiet` | Suppress progress bars and extra logging (good for pipes). | `False` |

### Example: High-Resilience Scan
Run a scan with extended timeouts for slow connections:
```bash
python cli.py --file huge_list.txt --timeout 20 --retries 5
```

---

## 🔍 Deep Dive: Strength Analysis
The `checker.py` engine runs 8 distinct checks to calculate a "Strength Score".

| Check | Condition | Logic |
| :--- | :--- | :--- |
| **Length** | `len >= 12` | Minimum standard for modern bruteforce resistance. |
| **Complexity** | 4 Checks | Requires Lowercase, Uppercase, Digits, and Special Characters. |
| **Patterns** | No Common | Rejects `123`, `abc`, `qwe`, `password`, `admin`. |
| **Repetition** | No Repeats | Rejects valid chars repeated 3+ times (e.g., `aaabbb`). |
| **Sequence** | No 3+ Seq | Rejects sequential runs like `123` or `abc`. |

**Scoring Tier:**
- **90%+**: `EXCELLENT`
- **75-89%**: `STRONG`
- **60-74%**: `MODERATE`
- **40-59%**: `WEAK`
- **<40%**: `CRITICAL`

---

## 🛡️ Safety & Operational Resilience

### ⚠️ Safety Warning
- **Real Breach Data**: This tool interacts with the live HIBP database. While we use K-Anonymity, you are technically pinging a public API.
- **Rate Limiting**: The tool uses an internal `asyncio.Semaphore(5)` to limit concurrent requests to 5 at a time. Aggressive modification of this limit may cause your IP to be temporarily blocked by HIBP (HTTP 429).

### Resilience Features
- **Exponential Backoff**: If the API returns a 429 (Too Many Requests), the tool automatically sleeps for `(2 ^ attempt) * 0.1s`.
- **Graceful Degradation**: If the API is completely unreachable, the tool will report a connection error but still provide the **Local Strength Analysis**.
- **Memory Hygiene**: Large lists are processed using generators where possible, and the `passwords` list is explicitly cleared (`.clear()`) in the `finally` block of `cli.py`.

---

## 🛠️ Technical Stack
| Category | Technology | Purpose |
| :--- | :--- | :--- |
| **Core** | Python 3.10+ | Logic & orchestration |
| **Network** | `aiohttp` | Async HTTP client for high-performance non-blocking API calls |
| **API** | HIBP v3 | K-Anonymity breach database |
| **UX** | `colorama` | ANSI color support for cross-platform terminal UI |
| **UX** | `tqdm` | Async progress bars for batch operations |
| **Testing** | `pytest` | (Recommended for contributors) |

---

## 🤝 Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for development instructions, code style, and testing guidelines.

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.

## 🙏 Acknowledgments
- Troy Hunt for the [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3).
- The Python security community for best practices on `hashlib` and `getpass`.
