package com.github.tls.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for KeyUsageConstants class.
 */
@ExtendWith(MockitoExtension.class)
class KeyUsageConstantsTest {

    private static final int EXPECTED_DIGITAL_SIGNATURE_BIT = 0;
    private static final int EXPECTED_NON_REPUDIATION_BIT = 1;
    private static final int EXPECTED_KEY_ENCIPHERMENT_BIT = 2;
    private static final int EXPECTED_DATA_ENCIPHERMENT_BIT = 3;
    private static final int EXPECTED_KEY_AGREEMENT_BIT = 4;
    private static final int EXPECTED_KEY_CERT_SIGN_BIT = 5;
    private static final int EXPECTED_CRL_SIGN_BIT = 6;
    private static final int EXPECTED_ENCIPHER_ONLY_BIT = 7;
    private static final int EXPECTED_DECIPHER_ONLY_BIT = 8;
    private static final int EXPECTED_KEY_USAGE_COUNT = 9;

    /**
     * Test KeyUsageConstants constructor throws exception (utility class).
     */
    @Test
    void testKeyUsageConstantsConstructorThrowsException() {
        assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            java.lang.reflect.Constructor<KeyUsageConstants> constructor =
                KeyUsageConstants.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            constructor.newInstance();
        });
    }

    /**
     * Test key usage bit constants.
     */
    @Test
    void testKeyUsageBitConstants() {
        assertEquals(EXPECTED_DIGITAL_SIGNATURE_BIT, KeyUsageConstants.DIGITAL_SIGNATURE_BIT);
        assertEquals(EXPECTED_NON_REPUDIATION_BIT, KeyUsageConstants.NON_REPUDIATION_BIT);
        assertEquals(EXPECTED_KEY_ENCIPHERMENT_BIT, KeyUsageConstants.KEY_ENCIPHERMENT_BIT);
        assertEquals(EXPECTED_DATA_ENCIPHERMENT_BIT, KeyUsageConstants.DATA_ENCIPHERMENT_BIT);
        assertEquals(EXPECTED_KEY_AGREEMENT_BIT, KeyUsageConstants.KEY_AGREEMENT_BIT);
        assertEquals(EXPECTED_KEY_CERT_SIGN_BIT, KeyUsageConstants.KEY_CERT_SIGN_BIT);
        assertEquals(EXPECTED_CRL_SIGN_BIT, KeyUsageConstants.CRL_SIGN_BIT);
        assertEquals(EXPECTED_ENCIPHER_ONLY_BIT, KeyUsageConstants.ENCIPHER_ONLY_BIT);
        assertEquals(EXPECTED_DECIPHER_ONLY_BIT, KeyUsageConstants.DECIPHER_ONLY_BIT);
    }

    /**
     * Test key usage count constant.
     */
    @Test
    void testKeyUsageCountConstant() {
        assertEquals(EXPECTED_KEY_USAGE_COUNT, KeyUsageConstants.KEY_USAGE_COUNT);
    }

    /**
     * Test key usage names array.
     */
    @Test
    void testKeyUsageNamesArray() {
        assertNotNull(KeyUsageConstants.KEY_USAGE_NAMES);
        assertEquals(EXPECTED_KEY_USAGE_COUNT, KeyUsageConstants.KEY_USAGE_NAMES.length);
        assertEquals("Digital Signature", KeyUsageConstants.KEY_USAGE_NAMES[EXPECTED_DIGITAL_SIGNATURE_BIT]);
        assertEquals("Non Repudiation", KeyUsageConstants.KEY_USAGE_NAMES[EXPECTED_NON_REPUDIATION_BIT]);
        assertEquals("Key Encipherment", KeyUsageConstants.KEY_USAGE_NAMES[EXPECTED_KEY_ENCIPHERMENT_BIT]);
        assertEquals("Data Encipherment", KeyUsageConstants.KEY_USAGE_NAMES[EXPECTED_DATA_ENCIPHERMENT_BIT]);
        assertEquals("Key Agreement", KeyUsageConstants.KEY_USAGE_NAMES[EXPECTED_KEY_AGREEMENT_BIT]);
        assertEquals("Key Cert Sign", KeyUsageConstants.KEY_USAGE_NAMES[EXPECTED_KEY_CERT_SIGN_BIT]);
        assertEquals("CRL Sign", KeyUsageConstants.KEY_USAGE_NAMES[EXPECTED_CRL_SIGN_BIT]);
        assertEquals("Encipher Only", KeyUsageConstants.KEY_USAGE_NAMES[EXPECTED_ENCIPHER_ONLY_BIT]);
        assertEquals("Decipher Only", KeyUsageConstants.KEY_USAGE_NAMES[EXPECTED_DECIPHER_ONLY_BIT]);
    }

    /**
     * Test that array length matches count constant.
     */
    @Test
    void testArrayLengthMatchesCount() {
        assertEquals(KeyUsageConstants.KEY_USAGE_COUNT, KeyUsageConstants.KEY_USAGE_NAMES.length);
    }

    /**
     * Test KeyUsageConstants class is final.
     */
    @Test
    void testKeyUsageConstantsClassIsFinal() {
        assertTrue(java.lang.reflect.Modifier.isFinal(KeyUsageConstants.class.getModifiers()));
    }

    /**
     * Test KeyUsageConstants package and class accessibility.
     */
    @Test
    void testKeyUsageConstantsPackageAndAccess() {
        assertEquals("com.github.tls.utils", KeyUsageConstants.class.getPackage().getName());
        assertTrue(java.lang.reflect.Modifier.isPublic(KeyUsageConstants.class.getModifiers()));
    }

    /**
     * Test that all constants are static and final.
     */
    @Test
    void testConstantsAreStaticAndFinal() throws NoSuchFieldException {
        java.lang.reflect.Field digitalSigField = KeyUsageConstants.class.getDeclaredField("DIGITAL_SIGNATURE_BIT");
        assertTrue(java.lang.reflect.Modifier.isStatic(digitalSigField.getModifiers()));
        assertTrue(java.lang.reflect.Modifier.isFinal(digitalSigField.getModifiers()));
        assertTrue(java.lang.reflect.Modifier.isPublic(digitalSigField.getModifiers()));

        java.lang.reflect.Field namesField = KeyUsageConstants.class.getDeclaredField("KEY_USAGE_NAMES");
        assertTrue(java.lang.reflect.Modifier.isStatic(namesField.getModifiers()));
        assertTrue(java.lang.reflect.Modifier.isFinal(namesField.getModifiers()));
        assertTrue(java.lang.reflect.Modifier.isPublic(namesField.getModifiers()));
    }

    /**
     * Test that no key usage names are null or empty.
     */
    @Test
    void testKeyUsageNamesAreNotNullOrEmpty() {
        for (int i = 0; i < KeyUsageConstants.KEY_USAGE_NAMES.length; i++) {
            String name = KeyUsageConstants.KEY_USAGE_NAMES[i];
            assertNotNull(name, "Key usage name at index " + i + " should not be null");
            assertFalse(name.trim().isEmpty(), "Key usage name at index " + i + " should not be empty");
        }
    }
}
