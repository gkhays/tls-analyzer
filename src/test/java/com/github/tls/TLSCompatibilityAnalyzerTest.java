package com.github.tls;

import java.security.KeyStore;
import java.security.Provider;
import java.util.Enumeration;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for TLSCompatibilityAnalyzer class.
 */
@ExtendWith(MockitoExtension.class)
class TLSCompatibilityAnalyzerTest {

    @Mock
    private KeyStore mockKeyStore;

    @Mock
    private SSLContext mockSSLContext;

    private TLSCompatibilityAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new TLSCompatibilityAnalyzer(mockKeyStore, mockSSLContext);
    }

    /**
     * Test TLSCompatibilityAnalyzer constructor.
     */
    @Test
    void testTLSCompatibilityAnalyzerConstructor() {
        assertNotNull(analyzer);
        assertTrue(analyzer instanceof TLSCompatibilityAnalyzer);
    }

    /**
     * Test constructor with null parameters.
     */
    @Test
    void testConstructorWithNullParameters() {
        assertDoesNotThrow(() -> {
            new TLSCompatibilityAnalyzer(null, null);
        });
    }

    /**
     * Test getTLSProtocol method.
     */
    @Test
    void testGetTLSProtocol() {
        when(mockSSLContext.getProtocol()).thenReturn("TLSv1.2");

        String protocol = analyzer.getTLSProtocol();
        assertEquals("TLSv1.2", protocol);
        verify(mockSSLContext).getProtocol();
    }

    /**
     * Test getTLSProtocol with null context.
     */
    @Test
    void testGetTLSProtocolWithNullContext() {
        TLSCompatibilityAnalyzer nullAnalyzer = new TLSCompatibilityAnalyzer(mockKeyStore, null);

        assertThrows(NullPointerException.class, () -> {
            nullAnalyzer.getTLSProtocol();
        });
    }

    /**
     * Test displayTLSInfo method.
     */
    @Test
    void testDisplayTLSInfo() {
        when(mockSSLContext.getProtocol()).thenReturn("TLSv1.2");
        Provider mockProvider = mock(Provider.class);
        when(mockProvider.getName()).thenReturn("SunJSSE");
        when(mockSSLContext.getProvider()).thenReturn(mockProvider);

        assertDoesNotThrow(() -> {
            analyzer.displayTLSInfo();
        });

        verify(mockSSLContext, atLeastOnce()).getProtocol();
        verify(mockSSLContext, atLeastOnce()).getProvider();
    }

    /**
     * Test displayCertificates method.
     */
    @Test
    void testDisplayCertificates() throws Exception {
        // Mock an empty enumeration for aliases
        Enumeration<String> emptyAliases = java.util.Collections.emptyEnumeration();
        when(mockKeyStore.aliases()).thenReturn(emptyAliases);

        assertDoesNotThrow(() -> {
            analyzer.displayCertificates();
        });
    }

    /**
     * Test TLSCompatibilityAnalyzer class structure.
     */
    @Test
    void testTLSCompatibilityAnalyzerClassStructure() {
        // Verify that TLSCompatibilityAnalyzer has the required methods
        assertDoesNotThrow(() -> {
            TLSCompatibilityAnalyzer.class.getDeclaredMethod("getTLSProtocol");
        });

        assertDoesNotThrow(() -> {
            TLSCompatibilityAnalyzer.class.getDeclaredMethod("displayTLSInfo");
        });

        assertDoesNotThrow(() -> {
            TLSCompatibilityAnalyzer.class.getDeclaredMethod("displayCertificates");
        });
    }

    /**
     * Test TLSCompatibilityAnalyzer package and class accessibility.
     */
    @Test
    void testTLSCompatibilityAnalyzerPackageAndAccess() {
        assertEquals("com.github.tls", TLSCompatibilityAnalyzer.class.getPackage().getName());
        assertTrue(java.lang.reflect.Modifier.isPublic(TLSCompatibilityAnalyzer.class.getModifiers()));
    }

    /**
     * Test constructor signature.
     */
    @Test
    void testConstructorSignature() {
        assertDoesNotThrow(() -> {
            TLSCompatibilityAnalyzer.class.getDeclaredConstructor(KeyStore.class, SSLContext.class);
        });
    }

    /**
     * Test analyzer with different SSL contexts.
     */
    @Test
    void testAnalyzerWithDifferentSSLContexts() {
        SSLContext mockContext1 = mock(SSLContext.class);
        SSLContext mockContext2 = mock(SSLContext.class);

        when(mockContext1.getProtocol()).thenReturn("TLSv1.2");
        when(mockContext2.getProtocol()).thenReturn("TLSv1.3");

        TLSCompatibilityAnalyzer analyzer1 = new TLSCompatibilityAnalyzer(mockKeyStore, mockContext1);
        TLSCompatibilityAnalyzer analyzer2 = new TLSCompatibilityAnalyzer(mockKeyStore, mockContext2);

        assertEquals("TLSv1.2", analyzer1.getTLSProtocol());
        assertEquals("TLSv1.3", analyzer2.getTLSProtocol());
    }
}
