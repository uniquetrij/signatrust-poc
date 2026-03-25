package com.signatrust.poc.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class KeystoreService {
    private static final Logger log = LoggerFactory.getLogger(KeystoreService.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Value("${signatrust.keystore.path:mock-hsm.p12}")
    private String keystorePath;

    @Value("${signatrust.keystore.password:changeit}")
    private String keystorePassword;

    @Value("${signatrust.keystore.alias:poc-signer}")
    private String keystoreAlias;

    private PrivateKey privateKey;
    private Certificate[] certificateChain;

    public PrivateKey getPrivateKey() { return privateKey; }
    public Certificate[] getCertificateChain() { return certificateChain; }

    @PostConstruct
    public void init() throws Exception {
        File ksFile = new File(keystorePath);
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        if (ksFile.exists()) {
            log.info("Loading existing Mock HSM Keystore from {}", ksFile.getAbsolutePath());
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                keyStore.load(fis, keystorePassword.toCharArray());
            }
        } else {
            log.info("Generating new Mock HSM Keystore at {}", ksFile.getAbsolutePath());
            keyStore.load(null, null);

            // Generate Key Pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            // Generate Self-Signed Cert
            X509Certificate cert = generateSelfSignedCertificate(keyPair);

            // Save to Keystore
            Certificate[] chain = new Certificate[]{cert};
            keyStore.setKeyEntry(keystoreAlias, keyPair.getPrivate(), keystorePassword.toCharArray(), chain);

            try (FileOutputStream fos = new FileOutputStream(ksFile)) {
                keyStore.store(fos, keystorePassword.toCharArray());
            }
            log.info("Mock HSM Keystore successfully generated.");
        }

        // Load keys into memory for fast signing
        privateKey = (PrivateKey) keyStore.getKey(keystoreAlias, keystorePassword.toCharArray());
        certificateChain = keyStore.getCertificateChain(keystoreAlias);
    }

    private X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year validity

        X500Name subjectDN = new X500Name("CN=SignaTrust PoC Mock HSM, O=SignaTrust, C=US");
        BigInteger serialNumber = BigInteger.valueOf(now);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subjectDN, serialNumber, startDate, endDate, subjectDN, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }
}
