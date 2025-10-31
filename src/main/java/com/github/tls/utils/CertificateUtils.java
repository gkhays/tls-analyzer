package com.github.tls.utils;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class providing common certificate operations shared between
 * TLSCompatibilityAnalyzer and CertificateManager.
 */
public final class CertificateUtils {

    /** Minimum RSA key size for TLS 1.3. */
    public static final int RSA_MIN_KEY_SIZE_TLS13 = 2048;
    /** Minimum RSA key size for TLS 1.2 and earlier. */
    public static final int RSA_MIN_KEY_SIZE_TLS12 = 1024;
    /** Minimum ECDSA key size for TLS 1.3. */
    public static final int ECDSA_MIN_KEY_SIZE_TLS13 = 256;
    /** Minimum ECDSA key size for TLS 1.2 and earlier. */
    public static final int ECDSA_MIN_KEY_SIZE_TLS12 = 224;
    /** Minimum DSA key size. */
    public static final int DSA_MIN_KEY_SIZE = 1024;

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateUtils.class);

    // Private constructor to prevent instantiation
    private CertificateUtils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * Checks the validity of a certificate with the given alias.
     *
     * @param keyStore the keystore containing the certificate
     * @param alias the alias of the certificate to check
     * @return true if the certificate is valid, false otherwise
     */
    public static boolean checkCertificateValidity(KeyStore keyStore, String alias) {
        if (keyStore == null) {
            LOGGER.error("KeyStore is null");
            return false;
        }

        try {
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            if (cert instanceof X509Certificate) {
                X509Certificate x509Cert = (X509Certificate) cert;
                x509Cert.checkValidity();
                LOGGER.debug("Certificate with alias '{}' is valid", alias);
                return true;
            } else {
                LOGGER.warn("No X509Certificate found for alias: {}", alias);
                return false;
            }
        } catch (java.security.cert.CertificateExpiredException e) {
            LOGGER.warn("Certificate with alias '{}' has expired", alias);
            return false;
        } catch (java.security.cert.CertificateNotYetValidException e) {
            LOGGER.warn("Certificate with alias '{}' is not yet valid", alias);
            return false;
        } catch (java.security.KeyStoreException e) {
            LOGGER.error("Error checking certificate validity for alias: " + alias, e);
            return false;
        }
    }

    /**
     * Enumerates all certificates in a keystore and applies a consumer function to each.
     *
     * @param keyStore the keystore to enumerate
     * @param certificateConsumer consumer function to apply to each certificate
     */
    public static void enumerateCertificates(KeyStore keyStore,
            CertificateConsumer certificateConsumer) {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    certificateConsumer.accept(alias, (X509Certificate) cert);
                }
            }
        } catch (java.security.KeyStoreException e) {
            LOGGER.error("Error accessing keystore", e);
        }
    }

    /**
     * Gets the key size from a public key.
     *
     * @param publicKey the public key to analyze
     * @return the key size in bits, or 0 if unknown
     */
    public static int getKeySize(java.security.PublicKey publicKey) {
        if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
            return ((java.security.interfaces.RSAPublicKey) publicKey).getModulus().bitLength();
        } else if (publicKey instanceof java.security.interfaces.ECPublicKey) {
            return ((java.security.interfaces.ECPublicKey) publicKey).getParams().getOrder().bitLength();
        } else if (publicKey instanceof java.security.interfaces.DSAPublicKey) {
            return ((java.security.interfaces.DSAPublicKey) publicKey).getParams().getP().bitLength();
        }
        return 0; // Unknown key type
    }

    /**
     * Checks if the key length is sufficient for the given TLS version.
     *
     * @param cert the certificate to check
     * @param tlsVersion the TLS version to check against
     * @return true if the key length is sufficient, false otherwise
     */
    public static boolean isKeyLengthSufficient(X509Certificate cert, String tlsVersion) {
        String keyAlgorithm = cert.getPublicKey().getAlgorithm();
        int keySize = getKeySize(cert.getPublicKey());

        if ("RSA".equals(keyAlgorithm)) {
            // RSA minimum key lengths
            if ("TLSv1.3".equals(tlsVersion)) {
                return keySize >= RSA_MIN_KEY_SIZE_TLS13; // TLS 1.3 requires at least 2048 bits for RSA
            } else if ("TLSv1.2".equals(tlsVersion)) {
                return keySize >= RSA_MIN_KEY_SIZE_TLS12; // TLS 1.2 minimum, but 2048 recommended
            }
            return keySize >= RSA_MIN_KEY_SIZE_TLS12; // Older TLS versions
        } else if ("EC".equals(keyAlgorithm) || "ECDSA".equals(keyAlgorithm)) {
            // ECDSA minimum key lengths
            if ("TLSv1.3".equals(tlsVersion)) {
                return keySize >= ECDSA_MIN_KEY_SIZE_TLS13; // TLS 1.3 requires at least P-256
            } else if ("TLSv1.2".equals(tlsVersion)) {
                return keySize >= ECDSA_MIN_KEY_SIZE_TLS12; // TLS 1.2 minimum
            }
            return keySize >= ECDSA_MIN_KEY_SIZE_TLS12;
        } else if ("DSA".equals(keyAlgorithm)) {
            // DSA is generally not recommended for TLS 1.3
            if ("TLSv1.3".equals(tlsVersion)) {
                return false;
            }
            return keySize >= DSA_MIN_KEY_SIZE;
        }

        // Unknown algorithm, assume compatible
        return true;
    }

    /**
     * Functional interface for consuming certificate information.
     */
    @FunctionalInterface
    public interface CertificateConsumer {
        /**
         * Accepts a certificate alias and certificate for processing.
         *
         * @param alias the certificate alias
         * @param certificate the X.509 certificate
         */
        void accept(String alias, X509Certificate certificate);
    }
}
