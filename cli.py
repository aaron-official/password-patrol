import argparse
import asyncio
import getpass
import sys
from pathlib import Path
from colorama import Fore, Style
from checker import PasswordChecker, PasswordSecurityError
from models import SecurityLevel
from utils import load_passwords_from_file

async def main():
    parser = argparse.ArgumentParser(
        description="Advanced Password Security Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s password123                    # Check single password
  %(prog)s -i                            # Interactive mode (secure input)
  %(prog)s -f passwords.txt              # Check passwords from file
  %(prog)s -b pwd1 pwd2 pwd3            # Check multiple passwords
  %(prog)s password123 --detailed        # Show detailed analysis
        """
    )
    # Remove 'passwords' from mutually exclusive group
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-i', '--interactive', action='store_true', help='Interactive mode with secure password input')
    group.add_argument('-f', '--file', type=Path, help='File containing passwords (one per line)')
    group.add_argument('-b', '--batch', nargs='+', help='Multiple passwords as arguments')
    parser.add_argument('passwords', nargs='*', help='Passwords to check (positional, not mutually exclusive)')
    parser.add_argument('--detailed', action='store_true', help='Show detailed analysis and recommendations')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--retries', type=int, default=3, help='Maximum retry attempts (default: 3)')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress indicators')
    args = parser.parse_args()
    passwords = []
    if args.interactive:
        password = getpass.getpass("Enter password to check (hidden): ")
        if not password:
            print("No password entered.")
            return 1
        passwords = [password]
    elif args.file:
        passwords = load_passwords_from_file(args.file)
    elif args.batch:
        passwords = args.batch
    else:
        passwords = args.passwords
    if not passwords:
        print("No passwords to check.")
        return 1
    if args.interactive:
        password = None
    print(f"\n{Fore.CYAN}Advanced Password Security Checker{Style.RESET_ALL}")
    print("=" * 50)
    try:
        async with PasswordChecker(
            timeout=args.timeout,
            max_retries=args.retries,
            enable_logging=not args.quiet
        ) as checker:
            if len(passwords) == 1:
                analysis = await checker.check_password(passwords[0])
                print(f"\nResults for password:")
                print(checker.format_result(analysis, args.detailed))
                if analysis.security_level in [SecurityLevel.CRITICAL, SecurityLevel.WEAK]:
                    return 1
            else:
                if not args.quiet:
                    print(f"\nChecking {len(passwords)} passwords...\n")
                results = await checker.check_passwords_batch(passwords)
                weak_count = 0
                for i, analysis in enumerate(results, 1):
                    print(f"\n--- Password {i} ---")
                    print(checker.format_result(analysis, args.detailed))
                    if analysis.security_level in [SecurityLevel.CRITICAL, SecurityLevel.WEAK]:
                        weak_count += 1
                print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
                print(f"Total passwords checked: {len(results)}")
                print(f"Weak/Critical passwords: {weak_count}")
                print(f"Strong passwords: {len(results) - weak_count}")
                if weak_count > 0:
                    print(f"\n{Fore.RED}⚠️  {weak_count} password(s) need immediate attention!{Style.RESET_ALL}")
                    return 1
                else:
                    print(f"\n{Fore.GREEN}✓ All passwords meet security standards{Style.RESET_ALL}")
    except PasswordSecurityError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return 1
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user{Style.RESET_ALL}")
        return 1
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        return 1
    finally:
        passwords.clear()
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
