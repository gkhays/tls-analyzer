# TLS Analyzer

A Java library for analyzing TLS/SSL configurations and certificate compatibility in Java applications. This tool helps developers verify that their certificates and TLS configurations meet security standards and are compatible with different TLS protocol versions.

## What It Does

TLS Analyzer provides comprehensive analysis of:

- **TLS Protocol Information**: Inspect SSL/TLS context details including protocol version and security provider
- **Certificate Compatibility**: Verify certificates against TLS 1.2 and TLS 1.3 requirements
- **Signature Algorithm Validation**: Check if certificate signature algorithms meet TLS security standards
- **Key Length Requirements**: Validate RSA, ECDSA, and DSA key lengths against TLS version requirements
- **Certificate Validity**: Check expiration dates and validity periods
- **Key Usage Verification**: Analyze X.509 key usage and extended key usage extensions for TLS compatibility

### Key Features

- ✅ Support for TLS 1.2 and TLS 1.3 compatibility checks
- ✅ Comprehensive certificate validation (validity, key length, signature algorithms)
- ✅ Key usage and extended key usage analysis
- ✅ Detailed logging with SLF4J
- ✅ Enumeration of all certificates in a KeyStore
- ✅ Validation against weak cryptographic algorithms (MD5, SHA-1)

## Quick Start

### Prerequisites

- Java 8 or higher
- Maven 3.6.3 or higher

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/gkhays/tls-analyzer.git
   cd tls-analyzer
   ```

2. **Build the project**:
   ```bash
   mvn clean install
   ```

3. **Run tests**:
   ```bash
   mvn test
   ```

### Usage Example

```java
import com.github.tls.TLSCompatibilityAnalyzer;
import javax.net.ssl.SSLContext;
import java.security.KeyStore;

// Load your keystore
KeyStore keyStore = KeyStore.getInstance("JKS");
// ... load keystore from file

// Get SSL context
SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
sslContext.init(null, null, null);

// Create analyzer
TLSCompatibilityAnalyzer analyzer = new TLSCompatibilityAnalyzer(keyStore, sslContext);

// Display TLS information
analyzer.displayTLSInfo();

// Check all certificates in the keystore
analyzer.displayCertificates();

// Check specific certificate compatibility
String alias = "my-certificate";
boolean isCompatible = analyzer.isCertificateCompatibleWithTLS(alias, "TLSv1.3");
System.out.println("Certificate compatible with TLS 1.3: " + isCompatible);
```

### Using Certificate Utilities

The library includes utility classes for common certificate operations:

```java
import com.github.tls.utils.CertificateUtils;
import java.security.cert.X509Certificate;

// Check if key length is sufficient for TLS version
boolean isSufficient = CertificateUtils.isKeyLengthSufficient(x509Cert, "TLSv1.3");

// Enumerate all certificates in a keystore
CertificateUtils.enumerateCertificates(keyStore, (alias, cert) -> {
    System.out.println("Certificate alias: " + alias);
    System.out.println("Subject: " + cert.getSubjectX500Principal());
});

// Check certificate validity
boolean isValid = CertificateUtils.checkCertificateValidity(keyStore, "my-cert-alias");
```

## Project Structure

```
tls-analyzer/
├── src/
│   ├── main/java/com/github/tls/
│   │   ├── TLSCompatibilityAnalyzer.java    # Main analyzer class
│   │   └── utils/
│   │       ├── CertificateUtils.java        # Certificate utility methods
│   │       └── KeyUsageConstants.java       # Key usage validation
│   └── test/java/com/github/tls/            # Unit tests
├── pom.xml
└── README.md
```

## Building and Testing

### Build the project
```bash
mvn clean package
```

### Run tests with coverage
```bash
mvn clean test jacoco:report
```

View coverage report at: `target/site/jacoco/index.html`

### Run code quality checks
```bash
mvn checkstyle:check
```

## Dependencies

- **SLF4J 2.0.16**: Logging facade
- **Logback 1.5.20**: Logging implementation
- **JUnit 5.6.0**: Testing framework
- **Mockito 5.2.0**: Mocking framework for tests

## Security Standards

The analyzer enforces the following security standards:

### TLS 1.3
- **Signature Algorithms**: SHA256, SHA384, or SHA512 with RSA, ECDSA, or RSA-PSS
- **RSA Key Size**: Minimum 2048 bits
- **ECDSA Key Size**: Minimum 256 bits

### TLS 1.2
- **Signature Algorithms**: Excludes weak algorithms (MD5, SHA-1 in certain contexts)
- **RSA Key Size**: Minimum 1024 bits (2048 bits recommended)
- **ECDSA Key Size**: Minimum 224 bits

### Rejected Algorithms
- MD5withRSA
- SHA1withRSA (for TLS 1.3)
- MD2withRSA
- MD5withDSA
- SHA1withDSA

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the terms specified in the LICENSE file.

## Author

[@gkhays](https://github.com/gkhays)
