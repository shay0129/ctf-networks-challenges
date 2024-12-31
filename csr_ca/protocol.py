"""
Protocol Configuration Module

This module contains all the configuration classes for the CTF challenge,
including certificates and network settings. All certificates are embedded
for easy distribution.

WARNING: This is CTF challenge code - not for production use!
"""

from typing import Final

class ClientConfig:
    """
    Client configuration settings.
    Includes hostnames and certificate settings.
    """
    HOSTNAME: Final[str] = "Pasdaran.local"
    HOSTNAME_REQUESTED: Final[str] = "ISRAEL"

class CAConfig:
    """
    Certificate Authority configuration settings.
    Includes network settings, organizational details, and certificates.
    """
    # Network Configuration
    IP: Final[str] = "10.0.0.1"
    PORT: Final[int] = 8443

    # Organization Details
    COUNTRY: Final[str] = "IR"
    STATE: Final[str] = "Tehran"
    CITY: Final[str] = "Tehran"
    ORG_NAME: Final[str] = "IRGC"
    ORG_UNIT: Final[str] = "Cybersecurity"
    HOSTNAME: Final[str] = "IRGC Root CA"
    CERT: Final[str] = """
-----BEGIN CERTIFICATE-----
MIIFVjCCAz4CCQDZlfjV/jlm3jANBgkqhkiG9w0BAQ0FADBtMQswCQYDVQQGEwJJ
UjEPMA0GA1UECAwGVGVocmFuMQ8wDQYDVQQHDAZUZWhyYW4xDTALBgNVBAoMBElS
R0MxFjAUBgNVBAsMDUN5YmVyc2VjdXJpdHkxFTATBgNVBAMMDElSR0MgUm9vdCBD
QTAeFw0yNDEyMTYxNDU4NTFaFw0yNTEyMTYxNDU4NTFaMG0xCzAJBgNVBAYTAklS
MQ8wDQYDVQQIDAZUZWhyYW4xDzANBgNVBAcMBlRlaHJhbjENMAsGA1UECgwESVJH
QzEWMBQGA1UECwwNQ3liZXJzZWN1cml0eTEVMBMGA1UEAwwMSVJHQyBSb290IENB
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiV5ILuOveVGLX70013yN
RCWXfa+fU9nmJjtX5ZU9dUFDXYYLjKt83IBgfvt4QfLup2ivZ99VbTp8m5cUpdem
NUTPZgh10zYDtqqTHEYFN+Z5QLWRDW0EbADB0oF2rIJXC3AChn+V6RQpFFQhNg1q
xkgeZOsiycAvCYMJoSQZEJcEV04aMz38yR5yCKdUmvBMaFbgp4mex6K1d5rASXWa
Hy1YMIkek+uGKaT/mBsW13eU7/+qfapckeYiU4Q7LvLw0WPnknFMCi7CrK9QO8ss
DPdvJjliwKFNLq+EAliCx479sybQrGQqEZwAV+rIUemCUDUlpDiO+yr0mGjVD0Rl
nyxuf+nXBKagoQFopGjzv/GGU8ZFP2DrVzbXx2dGARH+odAp+XDFVJ1amdZOpDZu
rcE1mf6ixKJsHEZhcDWBIKuBFv4v9g9qFnDu0BhNhI7ZEh3UcR/hM6O+9uJZiXi+
DwfzSB6S8LwyyyA1e0kmcenvtDGksZAzqb/70ypU85t5l9nV0rL1DiF1FpEFCpE+
6wUwjohczDiRkPaZlgonTPXEhpFLm9xy5mKvzkLzv49RHH1XQbU+mPQmtH6yqQcs
6tx0sWsXAZB08k0eJb5kjoOaIBXwQ0D/65QHyI7ywFP3KPbsxlFadBB4mJy3PioO
VamhxjkpwOy2mES83pq2K+8CAwEAATANBgkqhkiG9w0BAQ0FAAOCAgEAa9j+0bNW
WJQIoczrBBu4odTwhVZlU6hJFojSvan1il2Rnu8nwr4ZBgXnYedUqUZTGN3da6VX
ybys1GrnXJUr2m137TAYj5uKyaxHBGFI5tV/qfdyp7n/4YNmncQDRb8bD7oBTL4x
VXn4qwEKtm+CwVMgU9qhdjwaRFaLVKqUIC+V+xEjZATLm76jV0QOtwLicQTje3Yp
wS3k6eUHOa/YWdQjKTCZJBql7f6aBdnLIheElgbJbm5vK8mwW95dBncwIZj6409g
tGZTCziydmi4eO4oQLt/QgSzR0sGtZ7Rkf6UvNX1RuqZ8GOSH3JXf9n0/qTx5KcH
kz4Gb1bP3hW9HzE913XK3yuhXxPA1KADubrfBQJX4AK284QCwdFZpdorerU2ujCG
vSdjyXn3JiS6hzLd8zhCdRfns8VWI9VQtqeGEQa5mIuA29qFURLMKJe4/vcArXgw
FRaxCg+no1BwvyWcKXSgUT7A+qCgLGah7Gkj9KNo+mqnIfuRUi7Y3jhUbGi6N2YU
aoUyNx/igrds6l3kpnT1XbmMguWEx2IvMmIQlidkc2rM+j5VVI0HLtwg72NCOwfQ
kGUwuN75LdlEl2ALTpNeiXr6nwRPtVtzW4N0K5kJT3mw1OzX1wPjDWyiUWZhvP13
XtoeoJ/m/ocH/mzLvSuJqBoXFJ1KcD02Cug=
-----END CERTIFICATE-----
"""
    KEY: Final[str] = """
-----BEGIN PRIVATE KEY-----
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
Cilzn9gI0pCr0Gj0bNBxT9qPNQKOVYoc
-----END PRIVATE KEY-----
"""

class BurpConfig:
    """
    Burp Suite proxy configuration.
    Defines connection settings for intercepting proxy.
    """
    HOST: Final[str] = "127.0.0.1"  # Proxy host address
    PORT: Final[int] = 8080         # Proxy port number

class ProtocolConfig:
    """
    Network protocol configuration.
    Defines buffer sizes and connection timeouts.
    """
    # Buffer sizes
    MAX_MSG_LENGTH: Final[int] = 8192       # Maximum message buffer size
    SOCKET_BUFFER_SIZE: Final[int] = 4096   # Socket receive buffer size
    
    # Connection settings
    TIMEOUT: Final[int] = 60               # Connection timeout in seconds
    MAX_CONNECTIONS: Final[int] = 5        # Maximum concurrent connections