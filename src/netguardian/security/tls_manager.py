"""
netguardian.security.tls_manager — Certificate Authority & TLS Termination

Manages a local Root CA and dynamically generates per-domain certificates
for HTTPS interception. Integrates with asyncio stream wrappers for
transparent TLS termination in the proxy pipeline.

Refactored from the original src/tls.py with async support added.
"""

from __future__ import annotations

import os
import ssl
import time
from typing import Dict, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from netguardian.telemetry.logger import get_logger

_log = get_logger("netguardian.security.tls")


class CertificateManager:
    """
    Manages Root CA and generates domain certificates on-the-fly.

    Flow for HTTPS interception:
      1. Client sends CONNECT example.com:443
      2. Proxy calls get_certificate("example.com")
      3. This generates a cert signed by our CA for "example.com"
      4. Proxy presents that cert to the client (TLS termination)
      5. Proxy opens a real TLS connection to the actual example.com
    """

    def __init__(self, cert_dir: str = "certs", ca_name: str = "NetGuardian Root CA",
                 key_size: int = 2048):
        self.cert_dir = os.path.abspath(cert_dir)
        self.ca_name = ca_name
        self.key_size = key_size
        self.ca_cert_path = os.path.join(self.cert_dir, "ca.pem")
        self.ca_key_path = os.path.join(self.cert_dir, "ca.key")
        self._cert_cache: Dict[str, Tuple[bytes, bytes]] = {}
        self._init_ca()

    def _init_ca(self):
        """Load existing CA or generate a new self-signed Root CA."""
        os.makedirs(self.cert_dir, exist_ok=True)

        if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
            with open(self.ca_key_path, "rb") as f:
                self.ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            _log.info("Loaded existing CA certificate")
            return

        _log.info("Generating new Root CA certificate")
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self.key_size
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetGuardian Security"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "NetGuardian Proxy Engine"),
        ])

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(x509.datetime_from_timestamp(time.time() - 86400))
            .not_valid_after(x509.datetime_from_timestamp(time.time() + 315360000))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.ca_private_key, hashes.SHA256())
        )

        # Write CA key and cert to disk
        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def get_certificate(self, hostname: str) -> Tuple[str, str]:
        """
        Get or generate a certificate for `hostname`, signed by our CA.
        Returns (cert_path, key_path).
        """
        hostname = hostname.strip().lower()
        domain_cert_path = os.path.join(self.cert_dir, f"{hostname}.crt")
        domain_key_path = os.path.join(self.cert_dir, f"{hostname}.key")

        # Already on disk
        if os.path.exists(domain_cert_path) and os.path.exists(domain_key_path):
            return domain_cert_path, domain_key_path

        # In-memory cache hit — write to disk
        if hostname in self._cert_cache:
            cert_bytes, key_bytes = self._cert_cache[hostname]
            with open(domain_key_path, "wb") as f:
                f.write(key_bytes)
            with open(domain_cert_path, "wb") as f:
                f.write(cert_bytes)
            return domain_cert_path, domain_key_path

        # Generate new cert for this domain
        _log.debug(f"Generating certificate for {hostname}")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self.key_size
        )

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetGuardian Intercepted"),
        ])

        san = x509.SubjectAlternativeName([x509.DNSName(hostname)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(x509.datetime_from_timestamp(time.time() - 3600))
            .not_valid_after(x509.datetime_from_timestamp(time.time() + 31536000))
            .add_extension(san, critical=False)
            .sign(self.ca_private_key, hashes.SHA256())
        )

        key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

        self._cert_cache[hostname] = (cert_bytes, key_bytes)

        with open(domain_key_path, "wb") as f:
            f.write(key_bytes)
        with open(domain_cert_path, "wb") as f:
            f.write(cert_bytes)

        return domain_cert_path, domain_key_path

    def get_server_ssl_context(self, hostname: str) -> ssl.SSLContext:
        """SSLContext to present to the client (proxy mimics the target host)."""
        cert_path, key_path = self.get_certificate(hostname)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return context

    def get_client_ssl_context(self) -> ssl.SSLContext:
        """SSLContext for the proxy's outbound connection to the real server."""
        return ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    @property
    def cache_size(self) -> int:
        return len(self._cert_cache)
