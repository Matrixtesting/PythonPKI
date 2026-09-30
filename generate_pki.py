import argparse
import configparser
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


DEFAULT_CONFIG_FILE = "cfg.txt"

CA_KEY_FILENAME = "ca.key"
CA_CERT_FILENAME = "ca.pem"

SERVER_KEY_FILENAME = "server.key"
SERVER_CERT_FILENAME = "server.pem"

CLIENT_KEY_FILENAME = "client.key"
CLIENT_CERT_FILENAME = "client.pem"
CLIENT_P12_FILENAME = "client.p12"


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Generate a private CA and TLS server/client certificates."
    )

    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_FILE,
        help=f"Configuration file (default: {DEFAULT_CONFIG_FILE})",
    )

    parser.add_argument(
        "--recreate-ca",
        action="store_true",
        help=(
            "Explicitly replace the existing root CA. "
            "WARNING: previously issued certificates will no longer be trusted."
        ),
    )

    return parser.parse_args()


def load_config(config_path: Path) -> configparser.ConfigParser:
    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file '{config_path}' not found."
        )

    config = configparser.ConfigParser()
    config.read(config_path)

    return config


def require_config_value(
    config: configparser.ConfigParser,
    section: str,
    option: str,
) -> str:
    if not config.has_section(section):
        raise ValueError(f"Missing configuration section [{section}]")

    if not config.has_option(section, option):
        raise ValueError(
            f"Missing required configuration value: "
            f"[{section}] {option}"
        )

    value = config.get(section, option).strip()

    if not value:
        raise ValueError(
            f"Configuration value cannot be empty: "
            f"[{section}] {option}"
        )

    return value


def split_csv(value: str) -> list[str]:
    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def generate_rsa_key(bits: int) -> rsa.RSAPrivateKey:
    if bits < 2048:
        raise ValueError(
            f"RSA key size {bits} is too small. "
            "Use at least 2048 bits."
        )

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )


def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_private_key(
    path: Path,
    private_key: rsa.RSAPrivateKey,
):
    write_bytes(
        path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def write_certificate(
    path: Path,
    certificate: x509.Certificate,
):
    write_bytes(
        path,
        certificate.public_bytes(
            serialization.Encoding.PEM
        ),
    )


def build_name(
    config: configparser.ConfigParser,
    section: str,
) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                require_config_value(
                    config,
                    section,
                    "country",
                ),
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                require_config_value(
                    config,
                    section,
                    "organization",
                ),
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                require_config_value(
                    config,
                    section,
                    "common_name",
                ),
            ),
        ]
    )


def private_key_matches_certificate(
    private_key: rsa.RSAPrivateKey,
    certificate: x509.Certificate,
) -> bool:
    private_public_numbers = (
        private_key.public_key().public_numbers()
    )

    certificate_public_key = certificate.public_key()

    if not isinstance(
        certificate_public_key,
        rsa.RSAPublicKey,
    ):
        return False

    certificate_public_numbers = (
        certificate_public_key.public_numbers()
    )

    return (
        private_public_numbers ==
        certificate_public_numbers
    )


def load_existing_ca(
    ca_key_path: Path,
    ca_cert_path: Path,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key_exists = ca_key_path.exists()
    cert_exists = ca_cert_path.exists()

    if key_exists != cert_exists:
        raise RuntimeError(
            "Incomplete CA installation detected. "
            "Both ca.key and ca.pem must exist together."
        )

    if not key_exists:
        raise FileNotFoundError(
            "Existing CA does not exist."
        )

    ca_key = serialization.load_pem_private_key(
        ca_key_path.read_bytes(),
        password=None,
    )

    if not isinstance(ca_key, rsa.RSAPrivateKey):
        raise TypeError(
            "Existing CA private key is not an RSA key."
        )

    ca_cert = x509.load_pem_x509_certificate(
        ca_cert_path.read_bytes()
    )

    if not private_key_matches_certificate(
        ca_key,
        ca_cert,
    ):
        raise RuntimeError(
            "CA private key does not match CA certificate."
        )

    try:
        basic_constraints = ca_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise RuntimeError(
            "Existing CA certificate has no BasicConstraints extension."
        ) from exc

    if not basic_constraints.ca:
        raise RuntimeError(
            "Existing CA certificate is not marked as a CA."
        )

    return ca_key, ca_cert


def create_root_ca(
    config: configparser.ConfigParser,
    ca_key_path: Path,
    ca_cert_path: Path,
    now: datetime.datetime,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    ca_key = generate_rsa_key(
        config.getint(
            "ROOT_CA",
            "key_bits",
        )
    )

    ca_name = build_name(
        config,
        "ROOT_CA",
    )

    valid_days = config.getint(
        "ROOT_CA",
        "valid_days",
    )

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            now - datetime.timedelta(minutes=5)
        )
        .not_valid_after(
            now + datetime.timedelta(days=valid_days)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .sign(
            ca_key,
            hashes.SHA256(),
        )
    )

    write_private_key(
        ca_key_path,
        ca_key,
    )

    write_certificate(
        ca_cert_path,
        ca_cert,
    )

    return ca_key, ca_cert


def get_or_create_root_ca(
    config: configparser.ConfigParser,
    ca_dir: Path,
    now: datetime.datetime,
    recreate_ca: bool,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    ca_key_path = ca_dir / CA_KEY_FILENAME
    ca_cert_path = ca_dir / CA_CERT_FILENAME

    if recreate_ca:
        print(
            "WARNING: --recreate-ca specified. "
            "The existing CA will be replaced."
        )

        return create_root_ca(
            config,
            ca_key_path,
            ca_cert_path,
            now,
        )

    if ca_key_path.exists() or ca_cert_path.exists():
        print("Loading existing root CA.")

        return load_existing_ca(
            ca_key_path,
            ca_cert_path,
        )

    print("Creating new root CA.")

    return create_root_ca(
        config,
        ca_key_path,
        ca_cert_path,
        now,
    )


def build_server_san(
    config: configparser.ConfigParser,
) -> x509.SubjectAlternativeName:
    dns_names = split_csv(
        config.get(
            "SERVER",
            "san_dns",
            fallback="localhost",
        )
    )

    ip_addresses = split_csv(
        config.get(
            "SERVER",
            "san_ip",
            fallback="127.0.0.1",
        )
    )

    san_entries = []

    for dns_name in dns_names:
        san_entries.append(
            x509.DNSName(dns_name)
        )

    for ip_text in ip_addresses:
        san_entries.append(
            x509.IPAddress(
                ipaddress.ip_address(ip_text)
            )
        )

    if not san_entries:
        raise ValueError(
            "Server certificate must contain at least "
            "one DNS or IP Subject Alternative Name."
        )

    return x509.SubjectAlternativeName(
        san_entries
    )


def create_server_certificate(
    config: configparser.ConfigParser,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    server_dir: Path,
    now: datetime.datetime,
):
    server_key = generate_rsa_key(
        config.getint(
            "SERVER",
            "key_bits",
        )
    )

    server_name = build_name(
        config,
        "SERVER",
    )

    valid_days = config.getint(
        "SERVER",
        "valid_days",
    )

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            now - datetime.timedelta(minutes=5)
        )
        .not_valid_after(
            now + datetime.timedelta(days=valid_days)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,

                # TLS 1.3 does not use RSA key transport.
                key_encipherment=False,

                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH
                ]
            ),
            critical=False,
        )
        .add_extension(
            build_server_san(config),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                server_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .sign(
            ca_key,
            hashes.SHA256(),
        )
    )

    write_private_key(
        server_dir / SERVER_KEY_FILENAME,
        server_key,
    )

    write_certificate(
        server_dir / SERVER_CERT_FILENAME,
        server_cert,
    )

    return server_key, server_cert


def create_client_certificate(
    config: configparser.ConfigParser,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    client_dir: Path,
    now: datetime.datetime,
):
    client_key = generate_rsa_key(
        config.getint(
            "CLIENT",
            "key_bits",
        )
    )

    client_name = build_name(
        config,
        "CLIENT",
    )

    client_email = require_config_value(
        config,
        "CLIENT",
        "san_email",
    )

    valid_days = config.getint(
        "CLIENT",
        "valid_days",
    )

    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            now - datetime.timedelta(minutes=5)
        )
        .not_valid_after(
            now + datetime.timedelta(days=valid_days)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name(
                        client_email
                    )
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                client_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .sign(
            ca_key,
            hashes.SHA256(),
        )
    )

    write_private_key(
        client_dir / CLIENT_KEY_FILENAME,
        client_key,
    )

    write_certificate(
        client_dir / CLIENT_CERT_FILENAME,
        client_cert,
    )

    p12_password = require_config_value(
        config,
        "CLIENT",
        "p12_password",
    ).encode("utf-8")

    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"EAP-TLS Client Identity",
        key=client_key,
        cert=client_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(
            p12_password
        ),
    )

    write_bytes(
        client_dir / CLIENT_P12_FILENAME,
        p12_data,
    )

    return client_key, client_cert


def print_certificate_summary(
    title: str,
    certificate: x509.Certificate,
):
    print()
    print(title)
    print("-" * len(title))
    print(f"Subject : {certificate.subject.rfc4514_string()}")
    print(f"Issuer  : {certificate.issuer.rfc4514_string()}")
    print(f"Serial  : {certificate.serial_number}")
    print(f"Expires : {certificate.not_valid_after_utc}")


def main():
    args = parse_arguments()

    config_path = Path(args.config)
    config = load_config(config_path)

    base_dir = Path(
        config.get(
            "PATHS",
            "base_dir",
            fallback="enterprise_pki",
        )
    )

    client_common_name = require_config_value(
        config,
        "CLIENT",
        "common_name",
    )

    ca_dir = base_dir / "ca"
    server_dir = base_dir / "server"
    client_dir = (
        base_dir
        / "clients"
        / client_common_name
        / "active"
    )

    for folder in (
        ca_dir,
        server_dir,
        client_dir,
    ):
        folder.mkdir(
            parents=True,
            exist_ok=True,
        )

    now = datetime.datetime.now(
        datetime.timezone.utc
    )

    ca_key, ca_cert = get_or_create_root_ca(
        config,
        ca_dir,
        now,
        args.recreate_ca,
    )

    _, server_cert = create_server_certificate(
        config,
        ca_key,
        ca_cert,
        server_dir,
        now,
    )

    _, client_cert = create_client_certificate(
        config,
        ca_key,
        ca_cert,
        client_dir,
        now,
    )

    print_certificate_summary(
        "Root CA",
        ca_cert,
    )

    print_certificate_summary(
        "TLS Server Certificate",
        server_cert,
    )

    print_certificate_summary(
        "Client / EAP-TLS Certificate",
        client_cert,
    )

    print()
    print("PKI generation complete.")
    print()
    print(f"PKI root       : {base_dir}")
    print(f"CA certificate : {ca_dir / CA_CERT_FILENAME}")
    print(f"Server cert    : {server_dir / SERVER_CERT_FILENAME}")
    print(f"Server key     : {server_dir / SERVER_KEY_FILENAME}")
    print(f"Client cert    : {client_dir / CLIENT_CERT_FILENAME}")
    print(f"Client key     : {client_dir / CLIENT_KEY_FILENAME}")
    print(f"Client PKCS#12 : {client_dir / CLIENT_P12_FILENAME}")


if __name__ == "__main__":
    main()