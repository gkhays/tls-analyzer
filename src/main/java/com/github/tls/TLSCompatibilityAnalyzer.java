package com.github.tls;

import com.github.tls.utils.CertificateUtils;
import com.github.tls.utils.KeyUsageConstants;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TLS compatibility analyzer for analyzing SSL/TLS configurations and certificate compatibility.
 * This class provides utilities to inspect TLS protocols, certificates, and their compatibility
 * with different TLS versions.
 */
public class TLSCompatibilityAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(TLSCompatibilityAnalyzer.class);

    private KeyStore keyStore;
    private SSLContext context;

    /**
     * Constructs a new TLSCompatibilityAnalyzer with the specified keystore and SSL context.
     *
     * @param keyStore the keystore containing certificates to analyze
     * @param context the SSL context for TLS information
     */
    public TLSCompatibilityAnalyzer(KeyStore keyStore, SSLContext context) {
        this.keyStore = keyStore;
        this.context = context;
    }

    /**
     * Gets the TLS protocol version from the SSL context.
     *
     * @return the TLS protocol version
     */
    public String getTLSProtocol() {
        return context.getProtocol();
    }

    /**
     * Displays TLS protocol information including version and provider.
     */
    public void displayTLSInfo() {
        LOGGER.info("TLS Protocol: {}", context.getProtocol());
        LOGGER.info("Provider: {}", context.getProvider().getName());
    }

    /**
     * Displays certificates information from the keystore.
     */
    public void displayCertificates() {
        LOGGER.info("Certificates in KeyStore:");
        CertificateUtils.enumerateCertificates(keyStore, (alias, x509Cert) -> {
            LOGGER.info("Alias: {}", alias);
            boolean isCompatible = isCertificateCompatibleWithTLS(alias, context.getProtocol());
            boolean isSignatureOK = isSignatureAlgorithmCompatible(
                    x509Cert.getSigAlgName(), context.getProtocol());
            boolean isKeyLengthSufficient = CertificateUtils.isKeyLengthSufficient(x509Cert, context.getProtocol());
            LOGGER.info("  Compatible with {}: {}", context.getProtocol(), isCompatible);
            LOGGER.info("  Signature Algorithm OK: {}", isSignatureOK);
            LOGGER.info("  Key Length Sufficient: {}", isKeyLengthSufficient);
            LOGGER.debug("  Subject: {}", x509Cert.getSubjectX500Principal());
            LOGGER.debug("  Issuer: {}", x509Cert.getIssuerX500Principal());
            LOGGER.debug("  Valid From: {}", x509Cert.getNotBefore());
            LOGGER.debug("  Valid To: {}", x509Cert.getNotAfter());
            checkCertificateValidity(alias);
        });
    }

    /**
     * Checks the validity of a certificate with the given alias.
     *
     * @param alias the alias of the certificate to check
     */
    public void checkCertificateValidity(String alias) {
        CertificateUtils.checkCertificateValidity(keyStore, alias);
    }

    /**
     * Tests if a certificate is compatible with a given TLS version.
     * This method checks various aspects of the certificate including:
     * - Signature algorithm compatibility
     * - Key usage and extended key usage
     * - Key length requirements
     * - Certificate validity
     *
     * @param alias The alias of the certificate in the keystore
     * @param tlsVersion The TLS version to test compatibility against (e.g., "TLSv1.2", "TLSv1.3")
     * @return true if the certificate is compatible with the TLS version, false otherwise
     */
    public boolean isCertificateCompatibleWithTLS(String alias, String tlsVersion) {
        try {
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            if (!(cert instanceof X509Certificate)) {
                LOGGER.warn("Certificate with alias '{}' is not an X.509 certificate", alias);
                return false;
            }

            X509Certificate x509Cert = (X509Certificate) cert;

            // Check if certificate is valid (not expired or not yet valid)
            try {
                x509Cert.checkValidity();
            } catch (java.security.cert.CertificateExpiredException
                    | java.security.cert.CertificateNotYetValidException e) {
                LOGGER.warn("Certificate with alias '{}' is not valid: {}", alias, e.getMessage());
                return false;
            }

            // Check signature algorithm compatibility
            if (!isSignatureAlgorithmCompatible(x509Cert.getSigAlgName(), tlsVersion)) {
                LOGGER.warn("Certificate with alias '{}' has incompatible signature algorithm: {} for {}",
                           alias, x509Cert.getSigAlgName(), tlsVersion);
                return false;
            }

            // Check key length requirements
            if (!CertificateUtils.isKeyLengthSufficient(x509Cert, tlsVersion)) {
                LOGGER.warn("Certificate with alias '{}' has insufficient key length for {}", alias, tlsVersion);
                return false;
            }

            // Check key usage if present
            if (!KeyUsageConstants.isKeyUsageCompatibleWithTLS(x509Cert.getKeyUsage(), tlsVersion)) {
                LOGGER.warn("Certificate with alias '{}' has incompatible key usage for {}", alias, tlsVersion);
                return false;
            }

            LOGGER.info("Certificate with alias '{}' is compatible with {}", alias, tlsVersion);
            return true;

        } catch (java.security.KeyStoreException e) {
            LOGGER.error("Error checking certificate compatibility for alias: " + alias, e);
            return false;
        }
    }

    /**
     * Checks if the signature algorithm is compatible with the given TLS version.
     */
    private boolean isSignatureAlgorithmCompatible(String sigAlgName, String tlsVersion) {
        Set<String> weakAlgorithms = new HashSet<>(Arrays.asList(
            "MD5withRSA", "SHA1withRSA", "MD2withRSA", "MD5withDSA", "SHA1withDSA"
        ));

        // For TLS 1.3, be more restrictive
        if ("TLSv1.3".equals(tlsVersion)) {
            Set<String> tls13CompatibleAlgs = new HashSet<>(Arrays.asList(
                "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
                "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA",
                "SHA256withRSAPSS", "SHA384withRSAPSS", "SHA512withRSAPSS"
            ));
            return tls13CompatibleAlgs.contains(sigAlgName);
        }

        // For TLS 1.2 and earlier, just exclude known weak algorithms
        return !weakAlgorithms.contains(sigAlgName);
    }

}
