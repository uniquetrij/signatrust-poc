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
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import com.signatrust.poc.dto.SignaturePlacement;
import com.signatrust.poc.dto.SignRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Collections;
import java.util.List;

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

    @Operation(summary = "Preview generated signature graphics statelessly", description = "Test coordinates structurally. Returns visual footprint without BouncyCastle PKCS#7 seals.")
    @PostMapping(value = "/preview", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<Resource> previewPdf(
            @Parameter(description = "The original unsigned PDF document") @RequestPart("document") MultipartFile document,
            @Parameter(description = "Optional signature scribble graphics") @RequestPart(value = "signatureImage", required = false) MultipartFile signatureImage,
            @Parameter(description = "JSON structural configurations mapped purely for coordinate review") @RequestPart("signRequest") String signRequestStr,
            @Parameter(hidden = true) HttpServletRequest request) {

        try {
            String ipAddress = request.getHeader("X-Forwarded-For");
            if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
                ipAddress = request.getRemoteAddr();
            }
            if ("0:0:0:0:0:0:0:1".equals(ipAddress)) {
                ipAddress = "127.0.0.1";
            }

            byte[] imageBytes = signatureImage != null ? signatureImage.getBytes() : null;
            ObjectMapper mapper = new ObjectMapper();
            SignRequestDto signRequest = mapper.readValue(signRequestStr, SignRequestDto.class);

            List<SignaturePlacement> placements = signRequest.getPlacements();
            if (placements == null || placements.isEmpty()) {
                SignaturePlacement defaultPlacement = new SignaturePlacement();
                defaultPlacement.setPageNumber(1);
                defaultPlacement.setPositionX(50f);
                defaultPlacement.setPositionY(50f);
                defaultPlacement.setRotation(0f);
                placements = Collections.singletonList(defaultPlacement);
            }

            log.info("Generating unsigned coordinate preview for {}", signRequest.getSignerName());
            byte[] previewPdf = pdfSignerService.previewPdf(document.getBytes(), imageBytes, signRequest.getSignerName(), signRequest.getLocation(), ipAddress, placements);
            
            ByteArrayResource resource = new ByteArrayResource(previewPdf);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"preview-" + System.currentTimeMillis() + ".pdf\"")
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(resource);
        } catch (Exception e) {
            log.error("Failed to generate structural preview document", e);
            throw new RuntimeException("Document preview generation failed", e);
        }
    }

    @Operation(summary = "Cryptographically sign a PDF document", description = "Injects an optional visible signature scribble and cryptographically seals the PDF with the Mock HSM private key via CMS/PKCS#7.")
    @PostMapping(value = "/sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<Resource> signPdf(
            @Parameter(description = "The original PDF file to be signed") @RequestPart("document") MultipartFile document,
            @Parameter(description = "Optional transparent PNG image representing a physical signature scribble") @RequestPart(value = "signatureImage", required = false) MultipartFile signatureImage,
            @Parameter(description = "Signer metadata and placement configuration wrapped in JSON") @RequestPart("signRequest") String signRequestStr,
            @Parameter(hidden = true) HttpServletRequest request) {

        try {
            // Context injection
            String ipAddress = request.getHeader("X-Forwarded-For");
            if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
                ipAddress = request.getRemoteAddr();
            }
            if ("0:0:0:0:0:0:0:1".equals(ipAddress)) {
                ipAddress = "127.0.0.1";
            }

            byte[] imageBytes = signatureImage != null ? signatureImage.getBytes() : null;

            ObjectMapper mapper = new ObjectMapper();
            SignRequestDto signRequest = mapper.readValue(signRequestStr, SignRequestDto.class);

            String signerName = signRequest.getSignerName();
            String location = signRequest.getLocation();
            List<SignaturePlacement> placements = signRequest.getPlacements();

            if (placements == null || placements.isEmpty()) {
                // Backward compatibility / simplified testing default
                SignaturePlacement defaultPlacement = new SignaturePlacement();
                defaultPlacement.setPageNumber(1);
                defaultPlacement.setPositionX(50f);
                defaultPlacement.setPositionY(50f);
                defaultPlacement.setRotation(0f);
                placements = Collections.singletonList(defaultPlacement);
            }

            log.info("Received request to sign PDF for {}", signerName);
            byte[] signedPdf = pdfSignerService.signPdf(document.getBytes(), imageBytes, signerName, location, ipAddress, placements);

            long now = System.currentTimeMillis();
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"signed-" + now + ".pdf\"")
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(new ByteArrayResource(signedPdf));
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
