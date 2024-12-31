"""
Client-Server Protocol Configuration Module

Provides configuration classes for network settings, SSL certificates,
and communication parameters. All certificates are embedded for easy
distribution in this CTF challenge.

WARNING: This is CTF challenge code - not for production use!
"""
from typing import Final

class ServerConfig:
    """
    Server configuration including SSL certificates and network settings.
    Defines server identity and connection parameters.
    """
    IP: Final[str] = "127.0.0.1"
    PORT: Final[int] = 8444
    HOSTNAME: Final[str] = "Pasdaran.local"

    # Server SSL Certificate
    CERT: Final[str] = """
-----BEGIN CERTIFICATE-----
MIIFKzCCAxOgAwIBAgIUCSBG21YYAIFTfA8JIU2ExDc7eM0wDQYJKoZIhvcNAQEL
BQAwJTELMAkGA1UEBhMCSUwxFjAUBgNVBAMMDVBhc2RhcmFuTG9jYWwwHhcNMjQw
OTIyMDgwMzAyWhcNMjUwOTIyMDgwMzAyWjAlMQswCQYDVQQGEwJJTDEWMBQGA1UE
AwwNUGFzZGFyYW5Mb2NhbDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AJwM2Jk9HJ6f4N5siQy8taELtjxZ02BcPoDcO/6c5gGKCs2FyIFhNyC2Jy5ESYzT
VUFr1PJeRG/SpkRsmTBNIMhChLHgB+eKJwYwJGoTsZMUBmJDs+swR3W+AUKMyjp4
lAEGN9vfhY31Xl9E79AH2ubOb515Z/zE//eu0gIoyFWO4N4UrzDU4nyya+1y8Toz
LJPQglb4br4p9Riin/2yTLd87zgHBIqIIUkaFvrNjb+NrQWCQiq9lPvgNEsE+VGD
Z4OIrXgFKdbdgUhTLBNeuw5HYU4ZOQ69kPEyRgYe9CVBdbXvLEo53sVQedbbGXF/
oOPkVGK0ucOgzzcqWy6irzt9PvUA79dB2hYF4btPd9NkVjQzAfcEGz9scoZwX4hy
Ky7czpqpokI0IY7k8QtXQYa/3JuAAybMWfrQkHOYtq8zahBeLL4dPs1+ds9+8yWQ
ViPaQ5KUGQDU4G2LKJDDzxYgom+rcm15sSkNsbipWyixNctoUcbOKfeIv9y0Ynn2
6mnP0V0lW5YyZllSK/s8iUhaJi8bJctOnbFfvllcYp/42RLYutLUdL8IAsO1gaYt
JBG7LEzglWQkc3SsDt4KI8SmsJbHQUH86U2ipdNhnpAkMt8YkI/2ceiCZwqCh5Ol
ov/NWYbbuuE2PQL5eKZWkT350dY0IvjtDCHm+1ZQv7nJAgMBAAGjUzBRMB0GA1Ud
DgQWBBTKNFmPOxSZAPOSl1Tj0R6+KYAeCTAfBgNVHSMEGDAWgBTKNFmPOxSZAPOS
l1Tj0R6+KYAeCTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCG
FN6NSHuCf1VhxVW3Ei0s7xqX/PHVGUzuPHAy6bCH4DiTQbnEfeTth3K45uMnb8Ar
2x/0ZxQ20aap7fVGJt9xd3eLgijLeadyDZCveXrEKjkqSGwK15wZmp2zDsXv/X0G
E7gdOB/XGUvnFel/fLevXMhcwWo/McdXtuDZD657J1echhTa98JpiPXoHN0a4EBC
rljP6QAYqe2j3qBDnfwgKsBNMq+RVFd5HdJ0+aJWMmzUe0O5hVPyB3UR3tnbEMv5
UTFklp464P1q9JuY/RTOR3RgGGllUaInTdJsCx73+F4ea1JMKlzUze4z/39xw0TV
ZEfeBH2GvzPcqA7SizN64RvvjunqLMkYZ9Pf3Gd0/nRU0lMFSOI6BE5EF9CCCrIy
E6Br6l7RErvjJ664SpVDDkLSbP9liMWvrwPYtQBVHE4RPhut7uwXtdNXA3hOI1Qn
BAp5azqDc52OKfRygxPqYKbBJig4cEurJBCLnDbovnFHGtEn4ywVRm8UMv4pGT8b
9LWCvSWGExz6dmhHXMNWiM6orEbcN3q6djo0ZdlOw4MBcpm4lU3vvcLbQHBNuWZL
lSx9k5ETA/BHS4Poaj/W6ARzAPX2HytHirLiYf5zXXU2AcDOmm0A2hzVCUy22r2N
0a2XKGni1n+5WQ4b4p5h5rhM/5h+dlbkoAI4gVLjeA==
-----END CERTIFICATE-----
"""
    
    # Server Private Key
    KEY: Final[str] = """
-----BEGIN PRIVATE KEY-----
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
ymI0dErTaSUdX9bRn2wRGI+lsgM3aQ==
-----END PRIVATE KEY-----
"""
class ClientConfig:
    """
    Client configuration settings.
    Defines client identity and verification parameters.
    """
    HOSTNAME: Final[str] = "Pasdaran.local"
    HOSTNAME_REQUESTED: Final[str] = "ISRAEL"

class ProtocolConfig:
    """
    Network protocol settings.
    Defines buffer sizes, timeouts, and connection limits.
    """
    # Buffer sizes
    MAX_MSG_LENGTH: Final[int] = 8192      # Maximum message buffer size
    SOCKET_BUFFER_SIZE: Final[int] = 4096  # Socket receive buffer size
    
    # Connection parameters
    TIMEOUT: Final[int] = 60               # Connection timeout in seconds
    MAX_CONNECTIONS: Final[int] = 5        # Maximum concurrent connections

class SSLConfig:
    """
    SSL configuration settings.
    Defines encryption keys and related parameters.
    """
    ENCRYPTION_KEY: Final[bytes] = b"shay-ctf-2024"