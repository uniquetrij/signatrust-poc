package com.signatrust.poc.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.util.Collection;

@Service
public class SignatureVerifierService {
    private static final Logger log = LoggerFactory.getLogger(SignatureVerifierService.class);

    public String verifyPdf(byte[] signedPdfBytes) throws Exception {
        StringBuilder result = new StringBuilder();
        try (PDDocument document = Loader.loadPDF(signedPdfBytes)) {
            
            if (document.getSignatureDictionaries().isEmpty()) {
                return "Verification Failed: No signatures found in the document.";
            }

            for (PDSignature signature : document.getSignatureDictionaries()) {
                // The exact byte range of the PDF that was signed
                byte[] signedContent = signature.getSignedContent(new ByteArrayInputStream(signedPdfBytes));
                // The actual CMS/PKCS#7 signature block
                byte[] signatureContent = signature.getContents(new ByteArrayInputStream(signedPdfBytes));

                if (signatureContent == null || signedContent == null) {
                    continue;
                }

                // Verify the cryptographic structure utilizing BouncyCastle
                CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signedContent), signatureContent);
                Store<X509CertificateHolder> certStore = cms.getCertificates();
                SignerInformation signerInfo = cms.getSignerInfos().getSigners().iterator().next();

                Collection<X509CertificateHolder> certCollection = certStore.getMatches(signerInfo.getSID());
                X509CertificateHolder certHolder = certCollection.iterator().next();

                SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider("BC")
                        .build(certHolder);

                boolean isValid = signerInfo.verify(verifier);

                result.append("--- Signature Found ---\n")
                        .append("Signer Name: ").append(signature.getName()).append("\n")
                        .append("Location: ").append(signature.getLocation()).append("\n")
                        .append("Reason: ").append(signature.getReason()).append("\n")
                        .append("Date: ").append(signature.getSignDate().getTime()).append("\n")
                        .append("Mathmatically Valid: ").append(isValid ? "YES (Pass)" : "NO (Failed)").append("\n")
                        .append("Certificate Subject: ").append(certHolder.getSubject()).append("\n\n");
            }
        }
        return result.toString();
    }
}
