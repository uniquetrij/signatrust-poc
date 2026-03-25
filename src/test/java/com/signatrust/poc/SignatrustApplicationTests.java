package com.signatrust.poc;

import com.signatrust.poc.service.KeystoreService;
import com.signatrust.poc.service.PdfSignerService;
import com.signatrust.poc.service.SignatureVerifierService;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SignatrustApplicationTests {

    @Autowired
    private KeystoreService keystoreService;

    @Autowired
    private PdfSignerService pdfSignerService;

    @Autowired
    private SignatureVerifierService signatureVerifierService;

    @Test
    void contextLoadsAndKeystoreGenerates() {
        assertNotNull(keystoreService.getPrivateKey(), "Private Key should be generated and loaded into memory");
        assertNotNull(keystoreService.getCertificateChain(), "Certificate Chain should be generated and loaded");
        assertTrue(keystoreService.getCertificateChain().length > 0, "Certificate Chain should not be empty");
    }

    @Test
    void testEndToEndPdfSigningAndVerification() throws Exception {
        // 1. Create a minimal dummy PDF in-memory to act as our "document"
        byte[] dummyPdf;
        try (PDDocument doc = new PDDocument(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            doc.addPage(new PDPage());
            doc.save(baos);
            dummyPdf = baos.toByteArray();
        }

        // 2. Sign the PDF using our service (We omit the optional image for this automated test)
        byte[] signedPdf = pdfSignerService.signPdf(dummyPdf, null, "Automated Test Runner", "JUnit Test Env", "127.0.0.1");
        
        assertNotNull(signedPdf, "Signed PDF bytes should not be null");
        assertTrue(signedPdf.length > dummyPdf.length, "Signed PDF must be larger than original due to the embedded CMS/PKCS#7 cryptographic block");

        // 3. Verify the PDF utilizing the Verification Service
        String verificationReport = signatureVerifierService.verifyPdf(signedPdf);
        
        System.out.println("--- JUNIT TEST VERIFICATION REPORT ---");
        System.out.println(verificationReport);
        System.out.println("--------------------------------------");
        
        assertTrue(verificationReport.contains("Automated Test Runner"), "Report should correctly parse the signer metadata");
        assertTrue(verificationReport.contains("YES (Pass)"), "The CMS Signature block must cryptographically validate against the PDF hash and public cert");
    }
}
