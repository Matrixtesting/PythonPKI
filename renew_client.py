import argparse
import configparser
import datetime
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


DEFAULT_CONFIG_FILE = "cfg.txt"

CA_KEY_FILENAME = "ca.key"
CA_CERT_FILENAME = "ca.pem"

CLIENT_KEY_FILENAME = "client.key"
CLIENT_CERT_FILENAME = "client.pem"
CLIENT_P12_FILENAME = "client.p12"

MIN_RSA_KEY_BITS = 2048
CERT_CLOCK_SKEW_MINUTES = 5


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description=(
            "Renew an EAP-TLS client certificate using the "
            "existing private root CA."
        )
    )

    parser.add_argument(
        "-n",
        "--cn",
        help=(
            "Client Common Name. "
            "Example: device01@lab.local"
        ),
    )

    parser.add_argument(
        "-s",
        "--san",
        help=(
            "Client RFC822/email Subject Alternative Name. "
            "Example: device01@lab.local"
        ),
    )

    parser.add_argument(
        "-d",
        "--days",
        type=int,
        help="Certificate validity period in days.",
    )

    parser.add_argument(
        "-c",
        "--config",
        default=DEFAULT_CONFIG_FILE,
        help=(
            f"Configuration file "
            f"(default: {DEFAULT_CONFIG_FILE})."
        ),
    )

    password_group = parser.add_mutually_exclusive_group()

    password_group.add_argument(
        "-p",
        "--password",
        help=(
            "PKCS#12 export password. "
            "Note: command-line passwords may be visible "
            "in shell history or process listings."
        ),
    )

    password_group.add_argument(
        "--password-file",
        help=(
            "Read the PKCS#12 export password from a text file "
            "instead of the command line."
        ),
    )

    return parser.parse_args()


def load_config(
    config_path: Path,
) -> configparser.ConfigParser:
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
        raise ValueError(
            f"Missing configuration section [{section}]"
        )

    if not config.has_option(section, option):
        raise ValueError(
            f"Missing required configuration value: "
            f"[{section}] {option}"
        )

    value = config.get(
        section,
        option,
    ).strip()

    if not value:
        raise ValueError(
            f"Configuration value cannot be empty: "
            f"[{section}] {option}"
        )

    return value


def validate_client_directory_name(
    client_cn: str,
):
    """
    The CN is currently also used as the client's directory name.

    Reject characters that are unsafe or ambiguous in Windows
    path components rather than silently modifying the identity.
    """
    invalid_characters = '<>:"/\\|?*'

    if client_cn in (".", ".."):
        raise ValueError(
            "Client Common Name cannot be '.' or '..'."
        )

    if any(
        character in invalid_characters
        for character in client_cn
    ):
        raise ValueError(
            "Client Common Name contains a character that "
            "cannot safely be used in a Windows directory name."
        )

    if client_cn.endswith((" ", ".")):
        raise ValueError(
            "Client Common Name cannot end with a space or period."
        )

    if any(ord(character) < 32 for character in client_cn):
        raise ValueError(
            "Client Common Name contains control characters."
        )


def validate_rsa_key_size(
    key_bits: int,
):
    if key_bits < MIN_RSA_KEY_BITS:
        raise ValueError(
            f"RSA key size {key_bits} is too small. "
            f"Use at least {MIN_RSA_KEY_BITS} bits."
        )


def generate_rsa_key(
    key_bits: int,
) -> rsa.RSAPrivateKey:
    validate_rsa_key_size(key_bits)

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_bits,
    )


def private_key_matches_certificate(
    private_key: rsa.RSAPrivateKey,
    certificate: x509.Certificate,
) -> bool:
    certificate_public_key = certificate.public_key()

    if not isinstance(
        certificate_public_key,
        rsa.RSAPublicKey,
    ):
        return False

    return (
        private_key.public_key().public_numbers()
        ==
        certificate_public_key.public_numbers()
    )


def load_ca_credentials(
    ca_dir: Path,
    now: datetime.datetime,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    ca_key_path = ca_dir / CA_KEY_FILENAME
    ca_cert_path = ca_dir / CA_CERT_FILENAME

    key_exists = ca_key_path.exists()
    cert_exists = ca_cert_path.exists()

    if key_exists != cert_exists:
        raise RuntimeError(
            "Incomplete root CA installation. "
            "Both ca.key and ca.pem must exist."
        )

    if not key_exists:
        raise FileNotFoundError(
            f"Root CA files are missing in '{ca_dir}'."
        )

    ca_key = serialization.load_pem_private_key(
        ca_key_path.read_bytes(),
        password=None,
    )

    if not isinstance(
        ca_key,
        rsa.RSAPrivateKey,
    ):
        raise TypeError(
            "Root CA private key is not an RSA key."
        )

    ca_cert = x509.load_pem_x509_certificate(
        ca_cert_path.read_bytes()
    )

    if not private_key_matches_certificate(
        ca_key,
        ca_cert,
    ):
        raise RuntimeError(
            "Root CA private key does not match "
            "the root CA certificate."
        )

    try:
        basic_constraints = (
            ca_cert.extensions
            .get_extension_for_class(
                x509.BasicConstraints
            )
            .value
        )
    except x509.ExtensionNotFound as exc:
        raise RuntimeError(
            "Root CA certificate does not contain "
            "BasicConstraints."
        ) from exc

    if not basic_constraints.ca:
        raise RuntimeError(
            "Root CA certificate is not marked as a CA."
        )

    try:
        key_usage = (
            ca_cert.extensions
            .get_extension_for_class(
                x509.KeyUsage
            )
            .value
        )
    except x509.ExtensionNotFound as exc:
        raise RuntimeError(
            "Root CA certificate does not contain KeyUsage."
        ) from exc

    if not key_usage.key_cert_sign:
        raise RuntimeError(
            "Root CA certificate is not permitted "
            "to sign certificates."
        )

    if now < ca_cert.not_valid_before_utc:
        raise RuntimeError(
            "Root CA certificate is not yet valid."
        )

    if now >= ca_cert.not_valid_after_utc:
        raise RuntimeError(
            "Root CA certificate has expired."
        )

    return ca_key, ca_cert


def resolve_client_identity(
    args,
    config: configparser.ConfigParser,
) -> tuple[str, str]:
    if args.cn is not None:
        client_cn = args.cn.strip()
    else:
        client_cn = require_config_value(
            config,
            "CLIENT",
            "common_name",
        )

    if not client_cn:
        raise ValueError(
            "Client Common Name cannot be empty."
        )

    validate_client_directory_name(
        client_cn
    )

    if args.san is not None:
        san_email = args.san.strip()
    else:
        san_email = require_config_value(
            config,
            "CLIENT",
            "san_email",
        )

    if not san_email:
        raise ValueError(
            "Client SAN email cannot be empty."
        )

    """
     * Constructing RFC822Name here validates the identity
     * before any filesystem changes occur.
     """
    x509.RFC822Name(san_email)

    return client_cn, san_email


def resolve_valid_days(
    args,
    config: configparser.ConfigParser,
) -> int:
    if args.days is not None:
        valid_days = args.days
    else:
        valid_days = config.getint(
            "CLIENT",
            "valid_days",
        )

    if valid_days <= 0:
        raise ValueError(
            "Certificate validity must be greater than zero days."
        )

    return valid_days


def resolve_p12_password(
    args,
    config: configparser.ConfigParser,
) -> bytes:
    if args.password is not None:
        password = args.password

    elif args.password_file is not None:
        password_path = Path(
            args.password_file
        )

        if not password_path.exists():
            raise FileNotFoundError(
                f"Password file '{password_path}' not found."
            )

        password = (
            password_path
            .read_text(encoding="utf-8")
            .rstrip("\r\n")
        )

    else:
        password = require_config_value(
            config,
            "CLIENT",
            "p12_password",
        )

    if not password:
        raise ValueError(
            "PKCS#12 password cannot be empty."
        )

    return password.encode("utf-8")


def build_client_name(
    country: str,
    organization: str,
    client_cn: str,
) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                country,
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                organization,
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                client_cn,
            ),
        ]
    )


def generate_client_credentials(
    config: configparser.ConfigParser,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    client_cn: str,
    san_email: str,
    valid_days: int,
    p12_password: bytes,
    now: datetime.datetime,
) -> tuple[bytes, bytes, bytes, x509.Certificate]:
    country = require_config_value(
        config,
        "CLIENT",
        "country",
    )

    organization = require_config_value(
        config,
        "CLIENT",
        "organization",
    )

    key_bits = config.getint(
        "CLIENT",
        "key_bits",
    )

    client_key = generate_rsa_key(
        key_bits
    )

    client_name = build_client_name(
        country,
        organization,
        client_cn,
    )

    not_valid_before = (
        now -
        datetime.timedelta(
            minutes=CERT_CLOCK_SKEW_MINUTES
        )
    )

    not_valid_after = (
        now +
        datetime.timedelta(
            days=valid_days
        )
    )

    """
     * Do not issue a client certificate that outlives the
     * certificate authority that signed it.
    """
    if not_valid_after > ca_cert.not_valid_after_utc:
        raise ValueError(
            "Requested client certificate validity extends "
            "beyond the root CA expiration date.\n"
            f"Requested expiration: {not_valid_after}\n"
            f"CA expiration       : {ca_cert.not_valid_after_utc}"
        )

    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_cert.subject)
        .public_key(
            client_key.public_key()
        )
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            not_valid_before
        )
        .not_valid_after(
            not_valid_after
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
                        san_email
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

    key_bytes = client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_bytes = client_cert.public_bytes(
        serialization.Encoding.PEM
    )

    friendly_name = (
        f"EAP-TLS Client Identity - {client_cn}"
        .encode("utf-8")
    )

    p12_data = (
        pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=client_key,
            cert=client_cert,
            cas=[ca_cert],
            encryption_algorithm=(
                serialization.BestAvailableEncryption(
                    p12_password
                )
            ),
        )
    )

    return (
        key_bytes,
        cert_bytes,
        p12_data,
        client_cert,
    )


def create_unique_archive_path(
    archive_dir: Path,
    now: datetime.datetime,
) -> Path:
    timestamp = now.strftime(
        "%Y%m%d_%H%M%S_%fZ"
    )

    archive_path = (
        archive_dir /
        timestamp
    )

    counter = 1

    while archive_path.exists():
        archive_path = (
            archive_dir /
            f"{timestamp}_{counter}"
        )

        counter += 1

    return archive_path


def validate_staged_credentials(
    staging_dir: Path,
    p12_password: bytes,
):
    key_path = (
        staging_dir /
        CLIENT_KEY_FILENAME
    )

    cert_path = (
        staging_dir /
        CLIENT_CERT_FILENAME
    )

    p12_path = (
        staging_dir /
        CLIENT_P12_FILENAME
    )

    staged_key = (
        serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=None,
        )
    )

    if not isinstance(
        staged_key,
        rsa.RSAPrivateKey,
    ):
        raise RuntimeError(
            "Staged client key is not RSA."
        )

    staged_cert = (
        x509.load_pem_x509_certificate(
            cert_path.read_bytes()
        )
    )

    if not private_key_matches_certificate(
        staged_key,
        staged_cert,
    ):
        raise RuntimeError(
            "Staged client certificate and "
            "private key do not match."
        )

    (
        p12_key,
        p12_cert,
        _,
    ) = pkcs12.load_key_and_certificates(
        p12_path.read_bytes(),
        p12_password,
    )

    if p12_key is None or p12_cert is None:
        raise RuntimeError(
            "Staged PKCS#12 package does not contain "
            "both a private key and certificate."
        )

    if not isinstance(
        p12_key,
        rsa.RSAPrivateKey,
    ):
        raise RuntimeError(
            "PKCS#12 private key is not RSA."
        )

    if not private_key_matches_certificate(
        p12_key,
        p12_cert,
    ):
        raise RuntimeError(
            "PKCS#12 certificate and key do not match."
        )


def stage_new_credentials(
    staging_dir: Path,
    key_bytes: bytes,
    cert_bytes: bytes,
    p12_data: bytes,
    p12_password: bytes,
):
    staging_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:
        (
            staging_dir /
            CLIENT_KEY_FILENAME
        ).write_bytes(
            key_bytes
        )

        (
            staging_dir /
            CLIENT_CERT_FILENAME
        ).write_bytes(
            cert_bytes
        )

        (
            staging_dir /
            CLIENT_P12_FILENAME
        ).write_bytes(
            p12_data
        )

        validate_staged_credentials(
            staging_dir,
            p12_password,
        )

    except Exception:
        shutil.rmtree(
            staging_dir,
            ignore_errors=True,
        )

        raise


def activate_staged_credentials(
    client_base: Path,
    active_dir: Path,
    archive_dir: Path,
    staging_dir: Path,
    now: datetime.datetime,
) -> Path | None:
    archive_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    archived_path = None

    """
     * At this point the complete replacement credential set
     * already exists and has been validated in staging.
     """
    if active_dir.exists():
        if any(active_dir.iterdir()):
            archived_path = (
                create_unique_archive_path(
                    archive_dir,
                    now,
                )
            )

            active_dir.rename(
                archived_path
            )

        else:
            active_dir.rmdir()

    try:
        staging_dir.rename(
            active_dir
        )

    except Exception:
        """
         * If activation fails after archiving the old identity,
         * restore the old active directory when possible.
        """
        if (
            archived_path is not None
            and archived_path.exists()
            and not active_dir.exists()
        ):
            archived_path.rename(
                active_dir
            )

        raise

    return archived_path


def print_certificate_summary(
    certificate: x509.Certificate,
    client_cn: str,
    san_email: str,
    active_dir: Path,
):
    print()
    print("Client certificate renewed successfully.")
    print("----------------------------------------")
    print(f"Common Name : {client_cn}")
    print(f"SAN RFC822  : {san_email}")
    print(
        f"Serial      : "
        f"{certificate.serial_number}"
    )
    print(
        f"Valid from  : "
        f"{certificate.not_valid_before_utc}"
    )
    print(
        f"Valid until : "
        f"{certificate.not_valid_after_utc}"
    )
    print(f"Active path : {active_dir}")


def renew_client_certificate():
    args = parse_cli_args()

    config_path = Path(
        args.config
    )

    config = load_config(
        config_path
    )

    base_dir = Path(
        config.get(
            "PATHS",
            "base_dir",
            fallback="enterprise_pki",
        )
    )

    ca_dir = (
        base_dir /
        "ca"
    )

    client_cn, san_email = (
        resolve_client_identity(
            args,
            config,
        )
    )

    valid_days = resolve_valid_days(
        args,
        config,
    )

    p12_password = resolve_p12_password(
        args,
        config,
    )

    client_base = (
        base_dir /
        "clients" /
        client_cn
    )

    active_dir = (
        client_base /
        "active"
    )

    archive_dir = (
        client_base /
        "archive"
    )

    client_base.mkdir(
        parents=True,
        exist_ok=True,
    )

    now = datetime.datetime.now(
        datetime.timezone.utc
    )

    """
     * Validate the trust anchor before generating or modifying
     * any client credential directories.
     """
    ca_key, ca_cert = (
        load_ca_credentials(
            ca_dir,
            now,
        )
    )

    """
     * Generate and serialize the complete replacement identity
     * before touching the currently active credentials.
     """
    (
        key_bytes,
        cert_bytes,
        p12_data,
        new_client_cert,
    ) = generate_client_credentials(
        config,
        ca_key,
        ca_cert,
        client_cn,
        san_email,
        valid_days,
        p12_password,
        now,
    )

    timestamp = now.strftime(
        "%Y%m%d_%H%M%S_%fZ"
    )

    staging_dir = (
        client_base /
        f".renewal_{timestamp}"
    )

    """
     * Write and re-read the new PEM and PKCS#12 files to ensure
     * the replacement set is internally consistent before the
     * existing active identity is archived.
     """
    stage_new_credentials(
        staging_dir,
        key_bytes,
        cert_bytes,
        p12_data,
        p12_password,
    )

    try:
        archived_path = (
            activate_staged_credentials(
                client_base,
                active_dir,
                archive_dir,
                staging_dir,
                now,
            )
        )

    except Exception:
        shutil.rmtree(
            staging_dir,
            ignore_errors=True,
        )

        raise

    if archived_path is not None:
        print(
            "Archived previous active credentials to:"
        )
        print(
            f"  {archived_path}"
        )

    print_certificate_summary(
        new_client_cert,
        client_cn,
        san_email,
        active_dir,
    )


if __name__ == "__main__":
    renew_client_certificate()