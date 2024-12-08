# Symmetric Encryption Demo (NestJS Version)

This NestJS application demonstrates hierarchical key management and symmetric encryption using:

- Master Keys
- Key Encryption Keys (KEKs)
- Data Encryption Keys (DEKs)

## Key Concepts

1. **Master Key**: The root key used to derive KEKs
2. **Key Encryption Keys (KEKs)**: Derived from the master key, used to encrypt DEKs
3. **Data Encryption Keys (DEKs)**: Used for actual data encryption, protected by KEKs

## Features

- Session data encryption using DEKs
- KEK rotation capability
- Secure key derivation using PBKDF2
- AES encryption for data protection
- AWS KMS integration for enhanced security

## Implementations

### Local Implementation

- Uses local master key for key derivation
- Implements in-memory KEK and DEK management
- Suitable for demonstration and learning purposes

### AWS Implementation

- Integrates with AWS KMS for key management
- Uses AWS KMS for master key storage and data key generation
- Provides enhanced security through cloud-based key management
- Requires AWS credentials and KMS key setup

## Setup

1. Install dependencies:
```bash
npm install
```

2. Set environment variables (for AWS implementation):
```bash
export AWS_KMS_KEY_ID=your-kms-key-id
export AWS_REGION=your-aws-region
```

3. Run the application:
```bash
npm run start:dev
```

4. Open your browser and navigate to:
```
http://localhost:3000
```

## API Endpoints

### Local Key Management

- `POST /encryption/create-session`: Create a new encrypted session
- `GET /encryption/get-session`: Retrieve and decrypt session data
- `POST /encryption/rotate-kek`: Rotate the Key Encryption Key

### AWS KMS Integration

- `POST /encryption/aws/encrypt`: Encrypt data using AWS KMS
- `POST /encryption/aws/decrypt`: Decrypt data using AWS KMS

## Security Considerations

- Master keys should be stored securely in production
- AWS credentials should be properly configured
- Session secrets should be set via environment variables
- Use HTTPS in production environments

## Project Structure

```
.
├── src/
│   ├── encryption/
│   │   ├── key-manager.service.ts      # Local key management
│   │   ├── aws-key-manager.service.ts  # AWS KMS integration
│   │   ├── encryption.controller.ts    # API endpoints
│   │   └── encryption.module.ts        # Module configuration
│   ├── app.module.ts
│   └── main.ts
└── public/
    └── index.html                      # Web interface
