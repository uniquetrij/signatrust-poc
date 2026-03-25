# SignaTrust: Digital Signature PoC

A stateless, API-first Digital Signature microservice built with Spring Boot 3, Java 21, Apache PDFBox, and BouncyCastle.

## Local Setup
Requirements:
- Java 21
- Maven

To run the application locally:
```bash
mvn spring-boot:run
```
*(On first startup, the service will generate a Mock HSM Keystore `mock-hsm.p12` in the project root containing a self-signed RSA-2048 keypair).*

---

## API Documentation

### 1. Sign a PDF (`/api/v1/sign`)
Mathematically signs a PDF document. You can optionally include a `signatureImage` (a transparent PNG) to serve as the visual scribble on the document. The metadata coordinates (Date, IP, Location) will be automatically stamped.

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/sign \
  -F "document=@/path/to/sample.pdf" \
  -F "signatureImage=@/path/to/scribble.png" \
  -F "signerName=John Doe" \
  -F "location=Mumbai, India" \
  --output signed-document.pdf
```

### 2. Verify a PDF (`/api/v1/verify`)
Cryptographically verifies a signed PDF, analyzing the hash against the embedded public key certificate.

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/verify \
  -F "document=@signed-document.pdf"
```

## Docker Deployment
To build and run as a standalone container:
```bash
docker build -t signatrust-poc .
docker run -p 8080:8080 signatrust-poc
```
