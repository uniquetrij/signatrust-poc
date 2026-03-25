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

@RestController
@RequestMapping("/api/v1")
public class SignatureController {
    private static final Logger log = LoggerFactory.getLogger(SignatureController.class);

    private final PdfSignerService pdfSignerService;
    private final SignatureVerifierService signatureVerifierService;

    public SignatureController(PdfSignerService pdfSignerService, SignatureVerifierService signatureVerifierService) {
        this.pdfSignerService = pdfSignerService;
        this.signatureVerifierService = signatureVerifierService;
    }

    @PostMapping(value = "/sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> signPdf(
            @RequestParam("document") MultipartFile document,
            @RequestParam(value = "signatureImage", required = false) MultipartFile signatureImage,
            @RequestParam("signerName") String signerName,
            @RequestParam("location") String location,
            HttpServletRequest request) {

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

    @PostMapping(value = "/verify", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> verifyPdf(@RequestParam("document") MultipartFile document) {
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
