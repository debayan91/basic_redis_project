"""Comprehensive unit tests for indicator parsing, validation, normalization, and domain boundary logic."""

import pytest

from app.core.exceptions import InvalidIndicatorError
from app.services.indicator import IndicatorService, IndicatorType


class TestIPParsingAndNormalization:
    @pytest.mark.parametrize(
        "raw_ip,expected_canonical",
        [
            ("192.0.2.1", "192.0.2.1"),
            ("  10.0.0.1  ", "10.0.0.1"),
            ("172.16.0.5", "172.16.0.5"),
            ("8.8.8.8", "8.8.8.8"),
            ("255.255.255.255", "255.255.255.255"),
            ("0.0.0.0", "0.0.0.0"),
        ],
    )
    def test_valid_ipv4_parsing(self, raw_ip: str, expected_canonical: str) -> None:
        parsed = IndicatorService.parse_and_normalize(raw_ip)
        assert parsed.raw == raw_ip
        assert parsed.normalized == expected_canonical
        assert parsed.indicator_type == IndicatorType.IP
        assert parsed.is_ip is True
        assert parsed.is_ipv4 is True
        assert parsed.is_ipv6 is False
        assert parsed.extracted_domain is None

    @pytest.mark.parametrize(
        "raw_ip",
        [
            "10.0.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "172.16.0.1",
        ],
    )
    def test_ipv4_private_reserved_flag(self, raw_ip: str) -> None:
        parsed = IndicatorService.parse_and_normalize(raw_ip)
        assert parsed.is_private_or_reserved is True

    @pytest.mark.parametrize(
        "invalid_ip",
        [
            "256.0.0.1",
            "192.168.1",
            "192.168.1.1.1",
            "192.168.1.256",
            "abc.def.ghi.jkl",
            "",
            "   ",
        ],
    )
    def test_invalid_ipv4_rejected(self, invalid_ip: str) -> None:
        with pytest.raises(InvalidIndicatorError):
            IndicatorService.parse_and_normalize(invalid_ip, expected_type=IndicatorType.IP)

    @pytest.mark.parametrize(
        "raw_v6,expected_canonical",
        [
            ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"),
            ("2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"),
            ("::1", "::1"),
            ("fe80::1", "fe80::1"),
            ("2001:4860:4860::8888", "2001:4860:4860::8888"),
        ],
    )
    def test_valid_ipv6_parsing(self, raw_v6: str, expected_canonical: str) -> None:
        parsed = IndicatorService.parse_and_normalize(raw_v6)
        assert parsed.raw == raw_v6
        assert parsed.normalized == expected_canonical
        assert parsed.indicator_type == IndicatorType.IP
        assert parsed.is_ip is True
        assert parsed.is_ipv4 is False
        assert parsed.is_ipv6 is True

    @pytest.mark.parametrize(
        "invalid_v6",
        [
            "2001:xyz::1",
            "2001:db8:::1",
            "1200::AB00:1234::2552:7777:1313",
        ],
    )
    def test_invalid_ipv6_rejected(self, invalid_v6: str) -> None:
        with pytest.raises(InvalidIndicatorError):
            IndicatorService.parse_and_normalize(invalid_v6)


class TestDomainParsingAndNormalization:
    @pytest.mark.parametrize(
        "raw_domain,expected_canonical",
        [
            ("EXAMPLE.COM", "example.com"),
            ("sub.domain.example.co.uk", "sub.domain.example.co.uk"),
            ("threat-actor-site.net", "threat-actor-site.net"),
            ("threat-actor.org.", "threat-actor.org"),
            ("münchen.de", "xn--mnchen-3ya.de"),
            ("XN--MNCHEN-3YA.DE", "xn--mnchen-3ya.de"),
        ],
    )
    def test_valid_domain_normalization(self, raw_domain: str, expected_canonical: str) -> None:
        parsed = IndicatorService.parse_and_normalize(raw_domain)
        assert parsed.raw == raw_domain
        assert parsed.normalized == expected_canonical
        assert parsed.indicator_type == IndicatorType.DOMAIN
        assert parsed.extracted_domain == expected_canonical
        assert parsed.is_ip is False

    @pytest.mark.parametrize(
        "invalid_domain",
        [
            "localhost",  # Single label
            "com",  # TLD only
            "-invalid.com",  # Leading hyphen
            "invalid-.com",  # Trailing hyphen
            "invalid..com",  # Consecutive dots
            "192.168.1.1",  # IP is not a domain
            "example.123",  # All-numeric TLD
            "a" * 64 + ".com",  # Label exceeds 63 characters
            "invalid_domain.com",  # Underscore in domain label
            "",
            "   ",
        ],
    )
    def test_invalid_domains_rejected(self, invalid_domain: str) -> None:
        with pytest.raises(InvalidIndicatorError):
            IndicatorService.parse_and_normalize(invalid_domain, expected_type=IndicatorType.DOMAIN)


class TestURLParsingAndNormalization:
    def test_url_lowercase_scheme_and_host(self) -> None:
        parsed = IndicatorService.parse_and_normalize("HTTP://EXAMPLE.COM/Path/To/File")
        assert parsed.normalized == "http://example.com/Path/To/File"
        assert parsed.indicator_type == IndicatorType.URL
        assert parsed.extracted_domain == "example.com"
        assert parsed.raw == "HTTP://EXAMPLE.COM/Path/To/File"

    def test_url_strip_default_http_port(self) -> None:
        parsed = IndicatorService.parse_and_normalize("http://example.com:80/resource")
        assert parsed.normalized == "http://example.com/resource"

    def test_url_strip_default_https_port(self) -> None:
        parsed = IndicatorService.parse_and_normalize("https://example.com:443/secure")
        assert parsed.normalized == "https://example.com/secure"

    def test_url_keep_custom_port(self) -> None:
        parsed = IndicatorService.parse_and_normalize("https://example.com:8443/api")
        assert parsed.normalized == "https://example.com:8443/api"

    def test_url_discard_fragment(self) -> None:
        parsed = IndicatorService.parse_and_normalize("https://example.com/page#section-2")
        assert parsed.normalized == "https://example.com/page"

    def test_url_query_sorting_guarantees_consistency(self) -> None:
        url1 = "https://example.com/search?z=3&a=1&m=2"
        url2 = "https://example.com/search?a=1&m=2&z=3"
        parsed1 = IndicatorService.parse_and_normalize(url1)
        parsed2 = IndicatorService.parse_and_normalize(url2)
        assert parsed1.normalized == parsed2.normalized
        assert parsed1.normalized == "https://example.com/search?a=1&m=2&z=3"

    def test_url_path_resolution(self) -> None:
        parsed = IndicatorService.parse_and_normalize("https://example.com/a/b/../c/./d")
        assert parsed.normalized == "https://example.com/a/c/d"

    def test_url_preserves_trailing_slash(self) -> None:
        parsed = IndicatorService.parse_and_normalize("https://example.com/directory/")
        assert parsed.normalized == "https://example.com/directory/"

    def test_url_with_ip_host(self) -> None:
        parsed = IndicatorService.parse_and_normalize("http://192.0.2.1:8080/payload.bin")
        assert parsed.normalized == "http://192.0.2.1:8080/payload.bin"
        assert parsed.indicator_type == IndicatorType.URL
        assert parsed.extracted_domain is None

    def test_url_with_ipv6_host(self) -> None:
        parsed = IndicatorService.parse_and_normalize("https://[2001:db8::1]:8443/login")
        assert parsed.normalized == "https://[2001:db8::1]:8443/login"
        assert parsed.indicator_type == IndicatorType.URL

    def test_url_schemeless_with_path(self) -> None:
        parsed = IndicatorService.parse_and_normalize("bad-site.org/malware.exe")
        assert parsed.normalized == "http://bad-site.org/malware.exe"
        assert parsed.indicator_type == IndicatorType.URL
        assert parsed.extracted_domain == "bad-site.org"

    @pytest.mark.parametrize(
        "invalid_url",
        [
            "ftp://example.com/file.txt",  # Unsupported scheme
            "http://",  # Missing host
            "http://:8080/path",  # Missing host
            "http://example.com:99999/path",  # Out of range port
            "http://invalid_domain.com/path",  # Invalid domain in host
        ],
    )
    def test_invalid_urls_rejected(self, invalid_url: str) -> None:
        with pytest.raises(InvalidIndicatorError):
            IndicatorService.parse_and_normalize(invalid_url)


class TestDomainBoundaryLogic:
    """Rigorous tests ensuring domain-boundary semantics match expected cybersecurity behavior."""

    @pytest.mark.parametrize(
        "candidate,trusted_root,expected_match",
        [
            # Exact domain match
            ("google.com", "google.com", True),
            ("GOOGLE.COM", "google.com", True),
            ("google.com.", "google.com", True),
            ("google.com", ".google.com", True),
            # Direct subdomains
            ("mail.google.com", "google.com", True),
            ("accounts.google.com", "google.com", True),
            ("drive.google.com", "google.com", True),
            # Deep nested subdomains
            ("internal.api.v1.auth.google.com", "google.com", True),
            # URLs with matching host
            ("https://mail.google.com/inbox", "google.com", True),
            ("http://accounts.google.com:443/signin", "google.com", True),
            # CRITICAL NEGATIVE TEST CASES (Must NOT match)
            ("google.com.evil.com", "google.com", False),
            ("mail.google.com.attacker.org", "google.com", False),
            ("fakegoogle.com", "google.com", False),
            ("notgoogle.com", "google.com", False),
            ("mygoogle.com", "google.com", False),
            ("google.community", "google.com", False),
            ("google.co.uk", "google.com", False),
            ("https://google.com.evil.com/login", "google.com", False),
            ("https://evil-google.com/phish", "google.com", False),
            # IP address never matches trusted domain
            ("192.0.2.1", "google.com", False),
            ("http://192.0.2.1/path", "google.com", False),
        ],
    )
    def test_domain_boundary_matching(
        self, candidate: str, trusted_root: str, expected_match: bool
    ) -> None:
        match = IndicatorService.is_trusted_domain_match(candidate, trusted_root)
        assert match is expected_match, (
            f"Expected is_trusted_domain_match('{candidate}', '{trusted_root}') to be {expected_match}"
        )

    def test_extract_root_candidates(self) -> None:
        candidates = IndicatorService.extract_root_candidates("accounts.google.com")
        assert candidates == ["accounts.google.com", "google.com"]

        nested = IndicatorService.extract_root_candidates("a.b.c.example.com")
        assert nested == ["a.b.c.example.com", "b.c.example.com", "c.example.com", "example.com"]

        single = IndicatorService.extract_root_candidates("example.com")
        assert single == ["example.com"]


class TestNormalizationInvariants:
    @pytest.mark.parametrize(
        "indicator",
        [
            "192.0.2.1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "EXAMPLE.COM",
            "HTTPS://Accounts.Google.COM:443/login?z=2&a=1#frag",
            "münchen.de",
        ],
    )
    def test_normalization_idempotence(self, indicator: str) -> None:
        first_pass = IndicatorService.parse_and_normalize(indicator)
        second_pass = IndicatorService.parse_and_normalize(first_pass.normalized)
        assert first_pass.normalized == second_pass.normalized
        assert first_pass.indicator_type == second_pass.indicator_type
        assert first_pass.extracted_domain == second_pass.extracted_domain
