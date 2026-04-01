package com.signatrust.poc.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.util.Matrix;
import org.springframework.stereotype.Service;
import com.signatrust.poc.dto.SignaturePlacement;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Calendar;
import java.util.List;

@Service
public class PdfSignerService {
    private static final Logger log = LoggerFactory.getLogger(PdfSignerService.class);

    private final KeystoreService keystoreService;

    public PdfSignerService(KeystoreService keystoreService) {
        this.keystoreService = keystoreService;
    }

    public byte[] signPdf(byte[] originalPdf, byte[] signatureImage, String signerName, String location, String ipAddress,
                          List<SignaturePlacement> placements) throws Exception {
        try (PDDocument document = Loader.loadPDF(originalPdf);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            // 1. Visible Layer: Draw the user's scribble to the PDF *before* calculating the hash.
            applyVisualStamps(document, signatureImage, signerName, location, ipAddress, placements);

            // 2. Cryptographic Metadata Layer
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName(signerName);
            signature.setLocation(location);
            signature.setReason("SignaTrust PoC Extensible Document Signing");
            signature.setSignDate(Calendar.getInstance());

            // Add the signature dictionary to the document
            document.addSignature(signature);

            // 3. Initiate External Signing
            // This prepares the document's byte range, excluding the space where the signature will eventually go.
            ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(baos);

            // Fetch the bytes to hash
            InputStream hashStream = externalSigning.getContent();

            // Use our BouncyCastle helper to encrypt the hash with the private key
            CryptoSigner cryptoSigner = new CryptoSigner(keystoreService.getPrivateKey(), keystoreService.getCertificateChain());
            byte[] cmsSignature = cryptoSigner.sign(hashStream);

            // Inject the encrypted hash block into the reserved dictionary space
            externalSigning.setSignature(cmsSignature);

            return baos.toByteArray();
        }
    }

    public byte[] previewPdf(byte[] originalPdf, byte[] signatureImage, String signerName, String location, String ipAddress,
                             List<SignaturePlacement> placements) throws Exception {
        try (PDDocument document = Loader.loadPDF(originalPdf);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            // Purely structural visible layer without cryptographic signing blocks
            applyVisualStamps(document, signatureImage, signerName, location, ipAddress, placements);
            document.save(baos);
            return baos.toByteArray();
        }
    }

    private void applyVisualStamps(PDDocument document, byte[] signatureImage, String signerName, String location, String ipAddress, List<SignaturePlacement> placements) throws Exception {
        if (signatureImage == null || signatureImage.length == 0 || placements == null || placements.isEmpty()) {
            return;
        }
        
        PDImageXObject pdImage = PDImageXObject.createFromByteArray(document, signatureImage, "scribble");
        float imgWidth = 150;
        float imgHeight = (pdImage.getHeight() / (float) pdImage.getWidth()) * imgWidth;
        
        int totalPages = document.getNumberOfPages();

        for (SignaturePlacement placement : placements) {
            int pageIdx = (placement.getPageNumber() <= 0 || placement.getPageNumber() > totalPages) ? totalPages - 1 : placement.getPageNumber() - 1;
            PDPage targetPage = document.getPage(pageIdx);
            
            try (PDPageContentStream contentStream = new PDPageContentStream(document, targetPage, PDPageContentStream.AppendMode.APPEND, true, true)) {
                contentStream.saveGraphicsState();
                Matrix matrix = Matrix.getTranslateInstance(placement.getPositionX(), placement.getPositionY());
                matrix.rotate(Math.toRadians(placement.getRotation()));
                contentStream.transform(matrix);

                contentStream.drawImage(pdImage, 0, 0, imgWidth, imgHeight);

                // Overlay metadata text automatically below the signature
                contentStream.beginText();
                contentStream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 8);
                contentStream.newLineAtOffset(0, -10);
                contentStream.showText("Digitally signed by: " + signerName);
                contentStream.newLineAtOffset(0, -10);
                contentStream.showText("Date: " + Calendar.getInstance().getTime());
                contentStream.newLineAtOffset(0, -10);
                contentStream.showText("Location: " + location + " | IP: " + ipAddress);
                contentStream.endText();
                
                contentStream.restoreGraphicsState();
            }
        }
    }
}
