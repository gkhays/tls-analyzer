package com.github.tls.utils;

/**
 * Constants related to X.509 certificate key usage and extensions.
 */
public final class KeyUsageConstants {

    /** Key usage bit position for digital signature. */
    public static final int DIGITAL_SIGNATURE_BIT = 0;
    /** Key usage bit position for non-repudiation. */
    public static final int NON_REPUDIATION_BIT = 1;
    /** Key usage bit position for key encipherment. */
    public static final int KEY_ENCIPHERMENT_BIT = 2;
    /** Key usage bit position for data encipherment. */
    public static final int DATA_ENCIPHERMENT_BIT = 3;
    /** Key usage bit position for key agreement. */
    public static final int KEY_AGREEMENT_BIT = 4;
    /** Key usage bit position for key certificate signing. */
    public static final int KEY_CERT_SIGN_BIT = 5;
    /** Key usage bit position for CRL signing. */
    public static final int CRL_SIGN_BIT = 6;
    /** Key usage bit position for encipher only. */
    public static final int ENCIPHER_ONLY_BIT = 7;
    /** Key usage bit position for decipher only. */
    public static final int DECIPHER_ONLY_BIT = 8;

    /** Number of key usage types. */
    public static final int KEY_USAGE_COUNT = 9;

    /** Human-readable names for key usage types. */
    public static final String[] KEY_USAGE_NAMES = {
        "Digital Signature",      // bit 0
        "Non Repudiation",        // bit 1
        "Key Encipherment",       // bit 2
        "Data Encipherment",      // bit 3
        "Key Agreement",          // bit 4
        "Key Cert Sign",          // bit 5
        "CRL Sign",               // bit 6
        "Encipher Only",          // bit 7
        "Decipher Only"           // bit 8
    };

    // Private constructor to prevent instantiation
    private KeyUsageConstants() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * Checks if a specific key usage bit is set.
     *
     * @param keyUsage the key usage boolean array
     * @param bitPosition the bit position to check
     * @return true if the bit is set, false otherwise
     */
    public static boolean isKeyUsageSet(boolean[] keyUsage, int bitPosition) {
        return keyUsage != null && keyUsage.length > bitPosition && keyUsage[bitPosition];
    }

    /**
     * Gets the human-readable name for a key usage bit position.
     *
     * @param bitPosition the bit position
     * @return the human-readable name, or "Unknown" if invalid position
     */
    public static String getKeyUsageName(int bitPosition) {
        if (bitPosition >= 0 && bitPosition < KEY_USAGE_NAMES.length) {
            return KEY_USAGE_NAMES[bitPosition];
        }
        return "Unknown";
    }

    /**
     * Checks if the key usage is compatible with TLS requirements.
     *
     * @param keyUsage the key usage boolean array
     * @param tlsVersion the TLS version
     * @return true if compatible, false otherwise
     */
    public static boolean isKeyUsageCompatibleWithTLS(boolean[] keyUsage, String tlsVersion) {
        if (keyUsage == null) {
            // No key usage extension means all usages are allowed
            return true;
        }

        // For TLS server certificates, we typically need:
        // - Digital Signature (bit 0) OR Key Agreement (bit 4)
        // - Key Encipherment (bit 2) for RSA key exchange
        boolean hasDigitalSignature = isKeyUsageSet(keyUsage, DIGITAL_SIGNATURE_BIT);
        boolean hasKeyEncipherment = isKeyUsageSet(keyUsage, KEY_ENCIPHERMENT_BIT);
        boolean hasKeyAgreement = isKeyUsageSet(keyUsage, KEY_AGREEMENT_BIT);

        // For TLS 1.3, key encipherment is not used (only ECDHE/DHE)
        if ("TLSv1.3".equals(tlsVersion)) {
            return hasDigitalSignature || hasKeyAgreement;
        }

        // For TLS 1.2 and earlier, either digital signature or key encipherment is needed
        return hasDigitalSignature || hasKeyEncipherment || hasKeyAgreement;
    }
}
