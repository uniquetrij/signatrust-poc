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

For precise API schemas, start the server and visit the interactive **Swagger UI** mapping here:
`http://localhost:8080/swagger-ui/index.html`

### 1. Preview Signature Coordinates (`/api/v1/preview`)
A stateless helper route that accepts your exact `signRequest` JSON configuration layout and returns the visually stamped PDF identically to the final product **without executing the CMS cryptographic payload hashes**. Excellent for frontend verifications!

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/preview \
  -F "document=@sample.pdf" \
  -F "signatureImage=@scribble.png" \
  -F 'signRequest={
        "signerName": "John Doe",
        "location": "Mumbai, India",
        "placements": [
            { "pageNumber": 1, "positionX": 150.0, "positionY": 150.0, "rotation": 0.0 },
            { "pageNumber": 3, "positionX": 400.0, "positionY": 100.0, "rotation": 45.0 }
        ]
      }' \
  --output preview-document.pdf
```

### 2. Sign a PDF (`/api/v1/sign`)
Mathematically secures and signs the PDF document. Utilizes the exact same Multipart payload definition as `/preview`, but securely binds the document's SHA-256 byte payload to the internal private key generating an official PKCS#7 block.

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/sign \
  -F "document=@sample.pdf" \
  -F "signatureImage=@scribble.png" \
  -F 'signRequest={"signerName": "John Doe", "location": "Mumbai, India", "placements": []}' \
  --output signed-document.pdf
```

### 3. Verify a PDF (`/api/v1/verify`)
Cryptographically validates a signed PDF document natively, identifying public certificates, X-Forwarded-For origin IP addresses, and hash validation seals.

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
