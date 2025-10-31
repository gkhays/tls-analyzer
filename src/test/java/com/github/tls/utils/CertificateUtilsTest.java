package com.github.tls.utils;

import java.security.KeyStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for CertificateUtils class.
 */
@ExtendWith(MockitoExtension.class)
class CertificateUtilsTest {

    private static final int RSA_MIN_KEY_SIZE_TLS13_EXPECTED = 2048;
    private static final int RSA_MIN_KEY_SIZE_TLS12_EXPECTED = 1024;
    private static final int ECDSA_MIN_KEY_SIZE_TLS13_EXPECTED = 256;
    private static final int ECDSA_MIN_KEY_SIZE_TLS12_EXPECTED = 224;
    private static final int DSA_MIN_KEY_SIZE_EXPECTED = 1024;

    /**
     * Test CertificateUtils constructor throws exception (utility class).
     */
    @Test
    void testCertificateUtilsConstructorThrowsException() {
        assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            java.lang.reflect.Constructor<CertificateUtils> constructor =
                CertificateUtils.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            constructor.newInstance();
        });
    }

    /**
     * Test checkCertificateValidity method exists and handles exceptions.
     */
    @Test
    void testCheckCertificateValidityMethodExists() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        // Test with uninitialized keystore - should return false due to exception handling
        boolean result = CertificateUtils.checkCertificateValidity(keyStore, "testAlias");
        assertFalse(result);
    }

    /**
     * Test checkCertificateValidity with null keystore.
     */
    @Test
    void testCheckCertificateValidityWithNullKeyStore() {
        boolean result = CertificateUtils.checkCertificateValidity(null, "testAlias");
        assertFalse(result);
    }

    /**
     * Test checkCertificateValidity with null alias.
     */
    @Test
    void testCheckCertificateValidityWithNullAlias() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        boolean result = CertificateUtils.checkCertificateValidity(keyStore, null);
        assertFalse(result);
    }

    /**
     * Test checkCertificateValidity error handling.
     */
    @Test
    void testCheckCertificateValidityErrorHandling() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        // Test with uninitialized keystore and non-existent alias
        boolean result = CertificateUtils.checkCertificateValidity(keyStore, "nonExistentAlias");
        assertFalse(result);
    }

    /**
     * Test CertificateUtils constants.
     */
    @Test
    void testCertificateUtilsConstants() {
        assertEquals(RSA_MIN_KEY_SIZE_TLS13_EXPECTED, CertificateUtils.RSA_MIN_KEY_SIZE_TLS13);
        assertEquals(RSA_MIN_KEY_SIZE_TLS12_EXPECTED, CertificateUtils.RSA_MIN_KEY_SIZE_TLS12);
        assertEquals(ECDSA_MIN_KEY_SIZE_TLS13_EXPECTED, CertificateUtils.ECDSA_MIN_KEY_SIZE_TLS13);
        assertEquals(ECDSA_MIN_KEY_SIZE_TLS12_EXPECTED, CertificateUtils.ECDSA_MIN_KEY_SIZE_TLS12);
        assertEquals(DSA_MIN_KEY_SIZE_EXPECTED, CertificateUtils.DSA_MIN_KEY_SIZE);
    }

    /**
     * Test CertificateUtils class is final.
     */
    @Test
    void testCertificateUtilsClassIsFinal() {
        assertTrue(java.lang.reflect.Modifier.isFinal(CertificateUtils.class.getModifiers()));
    }

    /**
     * Test CertificateUtils package and class accessibility.
     */
    @Test
    void testCertificateUtilsPackageAndAccess() {
        assertEquals("com.github.tls.utils", CertificateUtils.class.getPackage().getName());
        assertTrue(java.lang.reflect.Modifier.isPublic(CertificateUtils.class.getModifiers()));
    }

    /**
     * Test checkCertificateValidity method exists and is static.
     */
    @Test
    void testCheckCertificateValidityMethodIsStatic() throws NoSuchMethodException {
        java.lang.reflect.Method method = CertificateUtils.class.getDeclaredMethod(
            "checkCertificateValidity", KeyStore.class, String.class);
        assertTrue(java.lang.reflect.Modifier.isStatic(method.getModifiers()));
        assertTrue(java.lang.reflect.Modifier.isPublic(method.getModifiers()));
    }
}
