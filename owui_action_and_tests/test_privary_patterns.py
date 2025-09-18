# test_privacy_patterns.py
import re
from typing import Dict, List, Tuple, Optional
import json

class PrivacyPatternTester:
    def __init__(self, patterns: Dict[str, str]):
        self.patterns = patterns
        self.results = {}
        
    def luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm"""
        # Remove non-digits
        digits = [int(c) for c in re.sub(r'\D', '', card_number)]
        if not (13 <= len(digits) <= 19):
            return False
        
        # Apply Luhn algorithm
        checksum = 0
        parity = len(digits) % 2
        for i, digit in enumerate(digits[:-1]):
            if i % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        
        return (checksum + digits[-1]) % 10 == 0

    def test_pattern(self, pattern_name: str, test_cases: List[Tuple[str, bool, Optional[str]]]) -> Dict:
        """
        Test a pattern against test cases
        Args:
            pattern_name: Name of the pattern
            test_cases: List of (text, should_match, expected_match)
        """
        pattern = self.patterns.get(pattern_name)
        if not pattern:
            return {"error": f"Pattern '{pattern_name}' not found"}
        
        results = {
            "pattern": pattern_name,
            "passed": 0,
            "failed": 0,
            "failures": []
        }
        
        for text, should_match, expected in test_cases:
            matches = re.findall(pattern, text, re.IGNORECASE if 'key' in pattern_name.lower() else 0)
            found = bool(matches)
            
            # Special handling for credit cards with Luhn check
            if pattern_name == "credit_card" and matches:
                matches = [m for m in matches if self.luhn_check(m)]
                found = bool(matches)
            
            if found == should_match:
                results["passed"] += 1
            else:
                results["failed"] += 1
                results["failures"].append({
                    "text": text,
                    "expected": should_match,
                    "found": found,
                    "matches": matches if matches else None
                })
                
        return results

    def run_all_tests(self) -> None:
        """Run all pattern tests"""
        
        # Phone number tests
        phone_intl_tests = [
            ("+1 555-123-4567", True, None),
            ("+44 20 7946 0958", True, None),
            ("+86 138 0000 0000", True, None),
            ("+33 1 23 45 67 89", True, None),
            ("not a phone", False, None),
            ("+999999999999999", False, None),  # Too long
            ("+1234", False, None),  # Too short
            ("+4917612345678", True, None),  # Digits-only international
        ]
        
        phone_us_tests = [
            ("(555) 123-4567", True, None),
            ("555-123-4567", True, None),
            ("555 123 4567", True, None),
            ("+1 555-123-4567", True, None),
            ("1-800-FLOWERS", False, None),  # Letters
            ("123-45-6789", False, None),  # SSN format
        ]
        
        phone_us_no_sep_tests = [
            ("8005551234", True, None),
            ("18005551234", True, None),
            ("5551234567", True, None),
            ("1234567890", False, None),  # Invalid area code
            ("0001234567", False, None),  # Invalid format
        ]
        
        # Email tests
        email_tests = [
            ("user@example.com", True, None),
            ("john.doe+filter@company.co.uk", True, None),
            ("test_email.123@sub.domain.org", True, None),
            ("invalid..email@test.com", False, None),  # Consecutive dots
            (".startswithdot@test.com", False, None),
            ("endswithdot.@test.com", False, None),
            ("@nodomain.com", False, None),
            ("noatsign.com", False, None),
            ("user@-example.com", False, None),  # domain label cannot start with hyphen
            ("user@example-.com", False, None),  # domain label cannot end with hyphen
            ("user.name+tag@sub-domain.example.co", True, None),
            ("user@sub_domain.com", False, None),  # underscore not allowed in domain
        ]
        
        # SSN tests
        ssn_tests = [
            ("123-45-6789", True, None),
            ("123 45 6789", True, None),
            ("123456789", True, None),
            ("000-12-3456", False, None),  # Invalid first group
            ("666-12-3456", False, None),  # Invalid 666
            ("900-12-3456", False, None),  # Invalid 900-999
            ("123-00-5678", False, None),  # Invalid middle
            ("123-45-0000", False, None),  # Invalid last
        ]
        
        # IP Address tests
        ip_tests = [
            ("192.168.1.1", True, None),
            ("10.0.0.0", True, None),
            ("255.255.255.255", True, None),
            ("8.8.8.8", True, None),
            ("256.1.1.1", False, None),  # Out of range
            ("192.168.1", False, None),  # Incomplete
            ("192.168.1.1.1", False, None),  # Too many octets
        ]
        
        ipv6_tests = [
            ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", True, None),
            ("2001:db8::8a2e:370:7334", True, None),
            ("::1", True, None),
            ("::ffff:192.0.2.1", False, None),  # IPv4 mapped (not in simple pattern)
            ("gggg::1", False, None),  # Invalid hex
            ("fe80::", True, None),  # link-local compressed
        ]
        
        # AWS Key tests
        aws_access_tests = [
            ("AKIAIOSFODNN7EXAMPLE", True, None),
            ("ASIATESTACCESSKEYEXAM", True, None),
            ("akiaiosfodnn7example", False, None),  # Lowercase
            ("AKIA123", False, None),  # Too short
        ]
        
        # API Key tests
        stripe_tests = [
            ("sk_test_4eC39HqLyjWDarjtT1zdp7dc", True, None),
            ("pk_live_TYooMQauvdEDq54NiTphI7jx", True, None),
            ("sk_4eC39HqLyjWDarjtT1zdp7dc", True, None),
            ("not_a_stripe_key", False, None),
        ]
        
        # Street Address tests
        address_tests = [
            ("123 Main Street", True, None),
            ("456 N Oak Avenue", True, None),
            ("789 South Elm Dr", True, None),
            ("1 Microsoft Way", True, None),
            ("42 Answer Boulevard", True, None),
            ("Just a street name", False, None),
            ("12345678 Too Long Number Street", False, None),
        ]
        
        # Credit Card tests (with Luhn validation)
        credit_tests = [
            ("4532015112830366", True, None),  # Valid Visa
            ("5425233430109903", True, None),  # Valid Mastercard
            ("374245455400126", True, None),   # Valid Amex
            ("4532-0151-1283-0366", True, None),  # With dashes
            ("4532 0151 1283 0366", True, None),  # With spaces
            ("4532015112830367", False, None),  # Invalid Luhn
            ("1234567890123456", False, None),  # Invalid Luhn
        ]
        
        # IBAN tests
        iban_tests = [
            ("GB82WEST12345698765432", True, None),
            ("DE89370400440532013000", True, None),
            ("FR1420041010050500013M02606", True, None),
            ("US12345678901234567890", False, None),  # US doesn't use IBAN
            ("GB82", False, None),  # Too short
            ("NL91ABNA0417164300", True, None),
        ]
        
        # Bitcoin address tests
        bitcoin_tests = [
            ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", True, None),
            ("3FenkBqRKNtBvmLN7MN8db7xWP3FfWYvdT", True, None),
            ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", True, None),
            ("invalidbitcoinaddress", False, None),
            ("1234567890", False, None),
        ]
        
        # Ethereum address tests
        ethereum_tests = [
            ("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb3", True, None),
            ("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", True, None),
            ("0xINVALID", False, None),
            ("742d35Cc6634C0532925a3b844Bc9e7595f0bEb3", False, None),  # Missing 0x
        ]
        
        # Run all tests
        test_suites = {
            "phone_intl": phone_intl_tests,
            "phone_us": phone_us_tests,
            "phone_us_no_sep": phone_us_no_sep_tests,
            "email": email_tests,
            "ssn": ssn_tests,
            "ip_address": ip_tests,
            "ipv6_address": ipv6_tests,
            "aws_access_key": aws_access_tests,
            "api_key_stripe": stripe_tests,
            "street_address": address_tests,
            "credit_card": credit_tests,
            "iban": iban_tests,
            "bitcoin_address": bitcoin_tests,
            "ethereum_address": ethereum_tests,
        }
        
        print("=" * 60)
        print("PRIVACY PATTERN TEST RESULTS")
        print("=" * 60)
        
        total_passed = 0
        total_failed = 0
        
        for pattern_name, test_cases in test_suites.items():
            if pattern_name in self.patterns:
                result = self.test_pattern(pattern_name, test_cases)
                self.results[pattern_name] = result
                
                total_passed += result["passed"]
                total_failed += result["failed"]
                
                status = "✓" if result["failed"] == 0 else "✗"
                print(f"\n{status} {pattern_name}: {result['passed']}/{result['passed'] + result['failed']} passed")
                
                if result["failures"]:
                    print("  Failures:")
                    for failure in result["failures"][:3]:  # Show first 3 failures
                        print(f"    - Text: '{failure['text'][:50]}...'")
                        print(f"      Expected: {failure['expected']}, Found: {failure['found']}")
        
        print("\n" + "=" * 60)
        print(f"TOTAL: {total_passed}/{total_passed + total_failed} tests passed")
        print("=" * 60)
        
        # Save detailed results to file
        with open("test_results.json", "w") as f:
            json.dump(self.results, f, indent=2)
            print("\nDetailed results saved to test_results.json")

    def test_real_world_text(self):
        """Test patterns against realistic text samples"""
        
        sample_text = """
        Please contact John Doe at john.doe@example.com or call him at (555) 123-4567.
        His office is at 123 Main Street, and his SSN is 123-45-6789 (just kidding!).
        
        Our server IP is 192.168.1.100 and the backup is at 10.0.0.50.
        
        Payment can be made with card 4532-0151-1283-0366 (test card).
        
        AWS Access Key: AKIAIOSFODNN7EXAMPLE
        Stripe Key: sk_test_4eC39HqLyjWDarjtT1zdp7dc
        
        Bitcoin donations: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        Ethereum: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb3
        """
        
        print("\n" + "=" * 60)
        print("REAL-WORLD TEXT SCAN")
        print("=" * 60)
        
        findings = {}
        for pattern_name, pattern in self.patterns.items():
            matches = re.findall(pattern, sample_text, re.IGNORECASE if 'key' in pattern_name.lower() else 0)
            
            # Special handling for credit cards
            if pattern_name == "credit_card" and matches:
                matches = [m for m in matches if self.luhn_check(m)]
            
            if matches:
                findings[pattern_name] = matches
        
        if findings:
            print("\nDetected sensitive data:")
            for pattern_name, matches in findings.items():
                print(f"  {pattern_name}: {matches}")
        else:
            print("\nNo sensitive data detected")

if __name__ == "__main__":
    from flywheel import PRIVACY_PATTERNS

    print("\nThis script validates privacy regex patterns used by flywheel.py.")
    print("How to run: `python3 test_privary_patterns.py`.")
    print("It prints per-pattern pass/fail, writes detailed JSON to `test_results.json`,")
    print("and scans a realistic text sample to show detected items.\n")

    tester = PrivacyPatternTester(PRIVACY_PATTERNS)
    tester.run_all_tests()
    tester.test_real_world_text()
