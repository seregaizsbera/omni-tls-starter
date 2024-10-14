package ru.github.seregaizsbera.tls.starter;

import sun.security.x509.X509CertImpl;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * Содержит общие данные для тестов.
 */
@SuppressWarnings("SpellCheckingInspection")
class TestData {
    private static final Object lock = new Object();
    private static TestData instance;
    final X509CertImpl realCert;

    private TestData(X509CertImpl realCert) {
        this.realCert = realCert;
    }

    static TestData getInstance() throws CertificateException {
        synchronized (lock) {
            if (instance == null) {
                instance = makeInstance();
            }
        }
        return instance;
    }

    private static TestData makeInstance() throws CertificateException {
        byte[] certData = (
                """
                        -----BEGIN CERTIFICATE-----
                        MIIG8zCCBdugAwIBAgISA2eYU38fZMIsj1fYF5YB6G0wMA0GCSqGSIb3DQEBCwUA
                        MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
                        EwJSMzAeFw0yMjA1MDgxMzEzMDRaFw0yMjA4MDYxMzEzMDNaMB4xHDAaBgNVBAMM
                        Eyouc3RhY2tleGNoYW5nZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
                        AoIBAQCtRnOt1h2+VqCqvx2m4GLtRbTRgdKqUx3e20hsvHs3Uz3Smq5QqHiuwsHA
                        cMHH3lWRbdAiB3FzYdmnnPnGa0BCzrZpBRgysTRhQGk7iFuqM9qPD63rwp8Cks92
                        LjmPuWamEp80pOkT/D/gU4nhQzIkYlSvbkRXS6VtdKXvmOBCZhP4ZCssPAxU1RjY
                        UWBz21mdxQWwj1N07FXgLyEPeUlzoNnwrtMX4j1Q+8/ZgVwjavquj5L0Qq+VsyiA
                        2dv1aBb16y2EkSqt153E9pGDCI68zSeM1S3qcTQtntn9WUYz9rDE5fqmCwlty3yq
                        3gGwUjuvh/q2FlJKRVQezk1o5NCJAgMBAAGjggQVMIIEETAOBgNVHQ8BAf8EBAMC
                        BaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAw
                        HQYDVR0OBBYEFI+VCCVshzJcLLzHLTAeafUmNr/XMB8GA1UdIwQYMBaAFBQusxe3
                        WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0
                        cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5j
                        ci5vcmcvMIIB5AYDVR0RBIIB2zCCAdeCDyouYXNrdWJ1bnR1LmNvbYISKi5ibG9n
                        b3ZlcmZsb3cuY29tghIqLm1hdGhvdmVyZmxvdy5uZXSCGCoubWV0YS5zdGFja2V4
                        Y2hhbmdlLmNvbYIYKi5tZXRhLnN0YWNrb3ZlcmZsb3cuY29tghEqLnNlcnZlcmZh
                        dWx0LmNvbYINKi5zc3RhdGljLm5ldIITKi5zdGFja2V4Y2hhbmdlLmNvbYITKi5z
                        dGFja292ZXJmbG93LmNvbYIVKi5zdGFja292ZXJmbG93LmVtYWlsgg8qLnN1cGVy
                        dXNlci5jb22CDWFza3VidW50dS5jb22CEGJsb2dvdmVyZmxvdy5jb22CEG1hdGhv
                        dmVyZmxvdy5uZXSCFG9wZW5pZC5zdGFja2F1dGguY29tgg9zZXJ2ZXJmYXVsdC5j
                        b22CC3NzdGF0aWMubmV0gg1zdGFja2FwcHMuY29tgg1zdGFja2F1dGguY29tghFz
                        dGFja2V4Y2hhbmdlLmNvbYISc3RhY2tvdmVyZmxvdy5ibG9nghFzdGFja292ZXJm
                        bG93LmNvbYITc3RhY2tvdmVyZmxvdy5lbWFpbIIRc3RhY2tzbmlwcGV0cy5uZXSC
                        DXN1cGVydXNlci5jb20wTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMB
                        AQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggED
                        BgorBgEEAdZ5AgQCBIH0BIHxAO8AdQDfpV6raIJPH2yt7rhfTj5a6s2iEqRqXo47
                        EsAgRFwqcwAAAYCkBETTAAAEAwBGMEQCIDnOQCaizj6AcOwTjnC/ITMfmhdna0Zr
                        3LxVV+dLzF4sAiAvtQehY1Y0+/4grAViGx/6/S/sLOn2loelt4Xk/MILLQB2AEal
                        Vet1+pEgMLWiiWn0830RLEF0vv1JuIWr8vxw/m1HAAABgKQERQEAAAQDAEcwRQIh
                        APiqfXK04vvB4jGYgzOtFzLIzcfkOyo9YXOsvGkmtHyVAiBV2gpMJ+ObOZaIB799
                        Wrfcg+d9FK7odihIp9WJRxm0RzANBgkqhkiG9w0BAQsFAAOCAQEAoPm4/7Mexrrl
                        vati1bl2CZdB72mySBqH9ph7Aw4DFQ1QFZxsDbhMNF38ppi0QHFIYNFnIa/l2pzm
                        NYPEU0uLGvHuVO+FSPXDpZ2eaexFQCM74tgsDXBYkaeCX+deS2r2q9zqsRKdg7KV
                        eZnvTvRBn44hScNh4J3x6WqWsjN+BGbSKf7BoLg9lcJoKPGH45nNGDSJnp6ZygNp
                        HH5NQZCWLD6yNtcMSLVfx1uT0/81o1H/EK+sz33Nbatb1oohpb2wJJwvvWX9BdbP
                        b6FndwamVLaeDF7MKij4r/CeAvgo9nRHP9Lbamwjz1Nh3uuRi0Io5NbzdVbTQf1o
                        7f2jfxR+2w==
                        -----END CERTIFICATE-----
                        """)
                .getBytes(StandardCharsets.ISO_8859_1);
        var cf = CertificateFactory.getInstance("X.509");
        var realCert = (X509CertImpl) cf.generateCertificate(new ByteArrayInputStream(certData));
        return new TestData(realCert);
    }
}
