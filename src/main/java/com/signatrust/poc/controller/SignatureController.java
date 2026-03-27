package com.signatrust.poc.controller;

import com.signatrust.poc.service.PdfSignerService;
import com.signatrust.poc.service.SignatureVerifierService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping("/api/v1")
@Tag(name = "Digital Signatures", description = "Endpoints for cryptographically signing and verifying PDF documents (DPI PoC)")
public class SignatureController {
    private static final Logger log = LoggerFactory.getLogger(SignatureController.class);

    private final PdfSignerService pdfSignerService;
    private final SignatureVerifierService signatureVerifierService;

    public SignatureController(PdfSignerService pdfSignerService, SignatureVerifierService signatureVerifierService) {
        this.pdfSignerService = pdfSignerService;
        this.signatureVerifierService = signatureVerifierService;
    }

    @Operation(summary = "Cryptographically sign a PDF document", description = "Injects an optional visible signature scribble and cryptographically seals the PDF with the Mock HSM private key via CMS/PKCS#7.")
    @PostMapping(value = "/sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> signPdf(
            @Parameter(description = "The original PDF file to be signed") @RequestParam("document") MultipartFile document,
            @Parameter(description = "Optional transparent PNG image representing a physical signature scribble") @RequestParam(value = "signatureImage", required = false) MultipartFile signatureImage,
            @Parameter(description = "Full name of the person signing the document") @RequestParam("signerName") String signerName,
            @Parameter(description = "Location where the signing takes place") @RequestParam("location") String location,
            @Parameter(hidden = true) HttpServletRequest request) {

        try {
            // Context injection
            String ipAddress = request.getRemoteAddr();
            byte[] imageBytes = signatureImage != null ? signatureImage.getBytes() : null;

            log.info("Received request to sign PDF for {}", signerName);
            byte[] signedPdf = pdfSignerService.signPdf(document.getBytes(), imageBytes, signerName, location, ipAddress);

            long now = System.currentTimeMillis();
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"signed-" + now + ".pdf\"")
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(signedPdf);
        } catch (Exception e) {
            log.error("Failed to sign document", e);
            throw new RuntimeException("Document signing failed", e);
        }
    }

    @Operation(summary = "Verify a digitally signed PDF", description = "Parses the PDF, extracts the embedded CMS signature block and public certificate, and verifies the cryptographic hash to ensure document integrity.")
    @PostMapping(value = "/verify", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> verifyPdf(
            @Parameter(description = "The digitally signed PDF file to verify") @RequestParam("document") MultipartFile document) {
        try {
            log.info("Received request to verify signed PDF.");
            String verificationResult = signatureVerifierService.verifyPdf(document.getBytes());
            return ResponseEntity.ok(verificationResult);
        } catch (Exception e) {
            log.error("Failed to verify document", e);
            return ResponseEntity.badRequest().body("Document verification failed: " + e.getMessage());
        }
    }
}
