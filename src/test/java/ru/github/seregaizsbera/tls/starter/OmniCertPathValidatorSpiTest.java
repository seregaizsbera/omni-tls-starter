package ru.github.seregaizsbera.tls.starter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@ExtendWith(MockitoExtension.class)
class OmniCertPathValidatorSpiTest {
    private CertificateFactory certFactory;
    private OmniCertPathValidatorSpi omniCertPathValidatorSpi;
    @Mock
    private X509Certificate certificate;
    @Mock
    private X509Certificate issuer;
    @Mock
    private X509Certificate root;
    private X500Principal principal1;
    private X500Principal principal2;
    private X500Principal principal3;
    private TestData testData;

    @BeforeEach
    void setUp() throws Exception {
        this.certFactory = CertificateFactory.getInstance("X.509");
        this.omniCertPathValidatorSpi = new OmniCertPathValidatorSpi();
        this.principal1 = new X500Principal("CN = stackexchange.com");
        this.principal2 = new X500Principal("CN = E6, O = Let's Encrypt, C = US");
        this.principal3 = new X500Principal("CN = ISRG Root X1, O = Internet Security Research Group, C = US");
        this.testData = TestData.getInstance();
    }

    @Test
    void testCompleteChain() throws GeneralSecurityException {
        when(certificate.getSubjectX500Principal()).thenReturn(principal1);
        when(certificate.getIssuerX500Principal()).thenReturn(principal2);
        when(certificate.getEncoded()).thenReturn(testData.cert().getEncoded());
        when(certificate.getPublicKey()).thenReturn(testData.cert().getPublicKey());

        when(issuer.getSubjectX500Principal()).thenReturn(principal2);
        when(issuer.getIssuerX500Principal()).thenReturn(principal3);
        when(issuer.getEncoded()).thenReturn(testData.issuer().getEncoded());
        when(issuer.getPublicKey()).thenReturn(testData.issuer().getPublicKey());
        when(issuer.getVersion()).thenReturn(testData.issuer().getVersion());
        when(issuer.getBasicConstraints()).thenReturn(testData.issuer().getBasicConstraints());

        when(root.getSubjectX500Principal()).thenReturn(principal3);
        when(root.getIssuerX500Principal()).thenReturn(principal3);
        when(root.getEncoded()).thenReturn(testData.root().getEncoded());
        when(root.getPublicKey()).thenReturn(testData.root().getPublicKey());
        when(root.getVersion()).thenReturn(testData.root().getVersion());
        when(root.getBasicConstraints()).thenReturn(testData.root().getBasicConstraints());

        CertPath certPath = certFactory.generateCertPath(List.of(certificate, issuer, root));
        Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(root, null));
        PKIXParameters pkixParameters = makePKIXParameters(trustAnchors);

        OmniTLSContext.push("testCompleteChain", 3);
        CertPathValidatorResult result = omniCertPathValidatorSpi.engineValidate(certPath, pkixParameters);

        assertNotNull(result, "Validator should return non-null result for valid cert path");
    }

    @Test
    void testIncompleteChain() throws GeneralSecurityException {
        when(certificate.getSubjectX500Principal()).thenReturn(principal1);
        when(certificate.getIssuerX500Principal()).thenReturn(principal2);
        when(certificate.getEncoded()).thenReturn(testData.cert().getEncoded());
        when(certificate.getPublicKey()).thenReturn(testData.cert().getPublicKey());
        when(certificate.getSerialNumber()).thenReturn(testData.cert().getSerialNumber());

        when(issuer.getSubjectX500Principal()).thenReturn(principal2);
        when(issuer.getIssuerX500Principal()).thenReturn(principal3);
        when(issuer.getEncoded()).thenReturn(testData.issuer().getEncoded());
        when(issuer.getPublicKey()).thenReturn(testData.issuer().getPublicKey());
        when(issuer.getVersion()).thenReturn(testData.issuer().getVersion());

        CertPath certPath = certFactory.generateCertPath(List.of(certificate));
        Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(issuer, null));
        PKIXParameters pkixParameters = makePKIXParameters(trustAnchors);

        OmniTLSContext.push("testIncompleteChain", 1);
        CertPathValidatorResult result = omniCertPathValidatorSpi.engineValidate(certPath, pkixParameters);

        assertNotNull(result, "Validator should return non-null result for valid cert path");
    }

    @Test
    void testBadParameters() throws CertificateException {
        CertPath certPath = certFactory.generateCertPath(Collections.singletonList(issuer));
        assertThrows(CertPathValidatorException.class, () -> omniCertPathValidatorSpi.engineValidate(certPath, null));
    }

    private static PKIXParameters makePKIXParameters(Set<TrustAnchor> trustAnchors) throws GeneralSecurityException {
        PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
        pkixParameters.setRevocationEnabled(false);
        return pkixParameters;
    }
}
