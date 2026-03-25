package com.signatrust.poc.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;

public class CryptoSigner implements SignatureInterface {
    private static final Logger log = LoggerFactory.getLogger(CryptoSigner.class);

    private final PrivateKey privateKey;
    private final Certificate[] certificateChain;

    public CryptoSigner(PrivateKey privateKey, Certificate[] certificateChain) {
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
    }

    @Override
    public byte[] sign(InputStream content) throws IOException {
        try {
            // Read the exact byte range of the PDF that needs to be hashed
            byte[] inputData = content.readAllBytes();

            List<Certificate> certList = Arrays.asList(certificateChain);
            JcaCertStore certs = new JcaCertStore(certList);

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            // Set up BouncyCastle signature generation
            Certificate cert = certificateChain[0];
            ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                    .setProvider("BC").build(privateKey);

            SignerInfoGenerator signerInfoGen = new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                    .build(sha256Signer, new X509CertificateHolder(cert.getEncoded()));

            gen.addSignerInfoGenerator(signerInfoGen);
            gen.addCertificates(certs);

            // Generate the PKCS#7 (CMS) signature block over the PDF hash
            CMSProcessableByteArray msg = new CMSProcessableByteArray(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"), inputData);
            CMSSignedData sigData = gen.generate(msg, false); // False = detached signature (payload is not duplicated in the signature block)

            return sigData.getEncoded();
        } catch (Exception e) {
            log.error("Failed to generate BouncyCastle signature.", e);
            throw new IOException("Failed to sign PDF hash", e);
        }
    }
}
