"""Indicator parsing, validation, normalization, and domain-boundary matching service."""

import ipaddress
import posixpath
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import idna

from app.core.exceptions import InvalidIndicatorError

# RFC 1035 compliant domain label regex: 1 to 63 alphanumeric or hyphen, no leading/trailing hyphen
DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

from app.schemas.indicator import IndicatorType, ParsedIndicator


class IndicatorService:
    """Service providing indicator parsing, validation, normalization, and domain boundary logic."""

    @staticmethod
    def validate_ipv4(value: str) -> ipaddress.IPv4Address | None:
        """Validate and return IPv4Address object, or None if invalid."""
        clean = value.strip()
        try:
            return ipaddress.IPv4Address(clean)
        except (ipaddress.AddressValueError, ValueError):
            return None

    @staticmethod
    def validate_ipv6(value: str) -> ipaddress.IPv6Address | None:
        """Validate and return IPv6Address object, or None if invalid."""
        clean = value.strip()
        try:
            return ipaddress.IPv6Address(clean)
        except (ipaddress.AddressValueError, ValueError):
            return None

    @classmethod
    def validate_ip(cls, value: str) -> tuple[bool, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
        """Validate if value is a valid IPv4 or IPv6 address."""
        clean = value.strip()
        v4 = cls.validate_ipv4(clean)
        if v4 is not None:
            return True, v4
        v6 = IndicatorService.validate_ipv6(clean)
        if v6 is not None:
            return True, v6
        return False, None

    @classmethod
    def validate_domain(cls, value: str) -> tuple[bool, str | None]:
        """Validate a domain name according to RFC 1034/1035 and IDNA specifications.
        
        Returns (is_valid, normalized_ascii_domain).
        """
        clean = value.strip().rstrip(".").lower()
        if not clean or len(clean) > 253:
            return False, None

        # Check if the domain is an IP address - an IP is not a domain
        is_ip, _ = cls.validate_ip(clean)
        if is_ip:
            return False, None

        # Encode to ASCII punycode for internationalized domain names (IDN)
        try:
            ascii_domain = idna.encode(clean).decode("ascii")
        except (idna.IDNAError, UnicodeError):
            return False, None

        labels = ascii_domain.split(".")
        # Valid domain must have at least 2 labels (e.g. example.com)
        if len(labels) < 2:
            return False, None

        for label in labels:
            if not label or len(label) > 63:
                return False, None
            if not DOMAIN_LABEL_REGEX.match(label):
                return False, None

        # TLD must not be all-numeric
        tld = labels[-1]
        if tld.isdigit():
            return False, None

        return True, ascii_domain

    @classmethod
    def validate_url(cls, value: str) -> tuple[bool, str | None, str | None]:
        """Validate a URL structure and extract normalized components.
        
        Returns (is_valid, canonical_url, extracted_hostname).
        """
        clean = value.strip()
        if not clean:
            return False, None, None

        # Determine scheme; if schemeless, use http for parsing
        has_scheme = "://" in clean
        parse_target = clean if has_scheme else f"http://{clean}"

        try:
            parsed = urlsplit(parse_target)
        except (ValueError, AttributeError):
            return False, None, None

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return False, None, None

        try:
            port = parsed.port
        except ValueError:
            return False, None, None

        if port is not None and (port < 1 or port > 65535):
            return False, None, None

        try:
            hostname = parsed.hostname
        except ValueError:
            return False, None, None

        if not hostname:
            return False, None, None

        raw_host = hostname.lower().strip()
        is_ip_host, ip_obj = cls.validate_ip(raw_host)

        extracted_domain: str | None = None
        if is_ip_host:
            assert ip_obj is not None
            norm_host_str = str(ip_obj)
            netloc_host = f"[{norm_host_str}]" if isinstance(ip_obj, ipaddress.IPv6Address) else norm_host_str
        else:
            is_dom, norm_domain = cls.validate_domain(raw_host)
            if not is_dom or norm_domain is None:
                return False, None, None
            netloc_host = norm_domain
            extracted_domain = norm_domain

        # Strip default ports (80 for http, 443 for https)
        if port is not None:
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                netloc = netloc_host
            else:
                netloc = f"{netloc_host}:{port}"
        else:
            netloc = netloc_host

        # Path normalization: resolve dot segments, preserve trailing slash
        path = parsed.path or "/"
        had_trailing_slash = path.endswith("/") and path != "/"
        norm_path = posixpath.normpath(path)
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        if had_trailing_slash and not norm_path.endswith("/"):
            norm_path += "/"

        # Query normalization: sort parameters for consistent key representation
        if parsed.query:
            query_tuples = parse_qsl(parsed.query, keep_blank_values=True)
            sorted_tuples = sorted(query_tuples, key=lambda x: (x[0], x[1]))
            norm_query = urlencode(sorted_tuples)
        else:
            norm_query = ""

        canonical_url = urlunsplit((scheme, netloc, norm_path, norm_query, ""))
        return True, canonical_url, extracted_domain

    @classmethod
    def parse_and_normalize(
        cls, raw_value: str, expected_type: IndicatorType | None = None
    ) -> ParsedIndicator:
        """Parse, validate, and normalize an indicator (IPv4, IPv6, Domain, URL).
        
        Preserves original raw input and raises InvalidIndicatorError on malformed input.
        """
        if not raw_value or not raw_value.strip():
            raise InvalidIndicatorError("Indicator cannot be empty.")

        clean = raw_value.strip()

        # 1. IP validation
        is_ip, ip_obj = cls.validate_ip(clean)
        if is_ip and ip_obj is not None:
            is_v4 = isinstance(ip_obj, ipaddress.IPv4Address)
            is_v6 = isinstance(ip_obj, ipaddress.IPv6Address)
            is_priv = (
                ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast
            )
            result = ParsedIndicator(
                raw=raw_value,
                normalized=str(ip_obj),
                indicator_type=IndicatorType.IP,
                extracted_domain=None,
                is_ip=True,
                is_ipv4=is_v4,
                is_ipv6=is_v6,
                is_private_or_reserved=is_priv,
            )
            if expected_type is not None and result.indicator_type != expected_type:
                raise InvalidIndicatorError(
                    f"Indicator '{raw_value}' identified as {result.indicator_type.value}, "
                    f"but expected {expected_type.value}."
                )
            return result

        # 2. Check for explicit URL scheme or schemeless URL containing path/query
        has_url_markers = (
            clean.lower().startswith(("http://", "https://"))
            or "/" in clean
            or "?" in clean
            or ("." in clean and ":" in clean and not clean.startswith("["))
        )

        if has_url_markers:
            is_url, canonical_url, extracted_domain = cls.validate_url(clean)
            if is_url and canonical_url is not None:
                result = ParsedIndicator(
                    raw=raw_value,
                    normalized=canonical_url,
                    indicator_type=IndicatorType.URL,
                    extracted_domain=extracted_domain,
                    is_ip=False,
                    is_ipv4=False,
                    is_ipv6=False,
                )
                if expected_type is not None and result.indicator_type != expected_type:
                    raise InvalidIndicatorError(
                        f"Indicator '{raw_value}' identified as {result.indicator_type.value}, "
                        f"but expected {expected_type.value}."
                    )
                return result
            raise InvalidIndicatorError(f"Malformed URL indicator: '{raw_value}'")

        # 3. Domain validation
        is_dom, norm_domain = cls.validate_domain(clean)
        if is_dom and norm_domain is not None:
            result = ParsedIndicator(
                raw=raw_value,
                normalized=norm_domain,
                indicator_type=IndicatorType.DOMAIN,
                extracted_domain=norm_domain,
                is_ip=False,
                is_ipv4=False,
                is_ipv6=False,
            )
            if expected_type is not None and result.indicator_type != expected_type:
                raise InvalidIndicatorError(
                    f"Indicator '{raw_value}' identified as {result.indicator_type.value}, "
                    f"but expected {expected_type.value}."
                )
            return result

        raise InvalidIndicatorError(
            f"Invalid indicator format: '{raw_value}'. Must be a valid IPv4, IPv6, Domain, or URL."
        )

    @classmethod
    def is_trusted_domain_match(cls, candidate: str, trusted_root: str) -> bool:
        """Evaluate whether a candidate (domain, hostname, or URL) matches a trusted root domain.
        
        Enforces strict domain-boundary semantics:
        - google.com -> match
        - mail.google.com -> match
        - accounts.google.com -> match
        - google.com.evil.com -> MUST NOT match
        - fakegoogle.com -> MUST NOT match
        """
        clean_trusted = trusted_root.strip().lower().strip(".")
        if not clean_trusted:
            return False

        # If candidate is a URL or has path/scheme, extract domain first
        clean_candidate = candidate.strip()
        if "://" in clean_candidate or "/" in clean_candidate:
            _, _, extracted = cls.validate_url(clean_candidate)
            if not extracted:
                return False
            domain_to_check = extracted.lower().strip(".")
        else:
            domain_to_check = clean_candidate.lower().strip(".")

        # Boundary checks:
        # 1. Exact match (e.g. 'google.com' == 'google.com')
        if domain_to_check == clean_trusted:
            return True

        # 2. Strict Subdomain match (must end with '.<trusted_root>')
        # e.g., 'mail.google.com'.endswith('.google.com') is True
        # but 'google.com.evil.com'.endswith('.google.com') is False!
        # and 'fakegoogle.com'.endswith('.google.com') is False!
        required_suffix = f".{clean_trusted}"
        return domain_to_check.endswith(required_suffix)

    @staticmethod
    def extract_root_candidates(domain: str) -> list[str]:
        """Generate hierarchical domain candidates from specific to root.
        
        Example: 'accounts.google.com' -> ['accounts.google.com', 'google.com']
        """
        clean = domain.strip().lower().rstrip(".")
        labels = clean.split(".")
        if len(labels) < 2:
            return [clean]

        return [".".join(labels[i:]) for i in range(len(labels) - 1)]

    @classmethod
    def extract_hostname(cls, indicator: str) -> str | None:
        """Extract and validate the domain hostname from an indicator, URL, or host string.
        
        Returns normalized ASCII domain hostname, or None if invalid or if host is an IP.
        """
        clean = indicator.strip()
        if not clean:
            return None

        # Check if clean string is directly an IP address
        is_ip, _ = cls.validate_ip(clean)
        if is_ip:
            return None

        # Parse via urlsplit to strip scheme, port, path, query, fragment
        target = clean if "://" in clean else f"//{clean}"

        try:
            parsed = urlsplit(target)
            host = parsed.hostname
        except ValueError:
            return None

        if not host:
            return None

        # Check if the extracted host is an IP
        is_ip_host, _ = cls.validate_ip(host)
        if is_ip_host:
            return None

        # Validate as a domain
        is_domain, norm_domain = cls.validate_domain(host)
        if is_domain and norm_domain:
            return norm_domain

        return None

