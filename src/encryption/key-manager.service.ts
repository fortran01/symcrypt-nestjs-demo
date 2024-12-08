import { Injectable } from '@nestjs/common';
import * as CryptoJS from 'crypto-js';
import { randomBytes } from 'crypto';

@Injectable()
export class KeyManagerService {
  private masterKey: Buffer;
  private keks: Map<string, { key: Buffer; salt: Buffer }>;
  private encryptedDeks: Map<string, string>;

  constructor() {
    // In production, this would be stored securely
    this.masterKey = Buffer.from(randomBytes(32));
    this.keks = new Map();
    this.encryptedDeks = new Map();
  }

  private deriveKek(kekId: string, salt?: Buffer): { key: Buffer; salt: Buffer } {
    if (!salt) {
      salt = Buffer.from(randomBytes(16));
    }

    // Use PBKDF2 for key derivation
    const key = CryptoJS.PBKDF2(
      Buffer.concat([this.masterKey, Buffer.from(kekId)]).toString('hex'),
      salt.toString('hex'),
      {
        keySize: 256 / 32, // 256 bits
        iterations: 100000,
      },
    );

    const derivedKey = Buffer.from(key.toString(), 'hex');
    this.keks.set(kekId, { key: derivedKey, salt });

    return { key: derivedKey, salt };
  }

  generateDek(kekId: string): Buffer {
    if (!this.keks.has(kekId)) {
      this.deriveKek(kekId);
    }

    // Generate new DEK
    const dek = Buffer.from(randomBytes(32));
    const kek = this.keks.get(kekId);

    // Encrypt DEK with KEK using AES
    const encrypted = CryptoJS.AES.encrypt(
      dek.toString('hex'),
      kek.key.toString('hex'),
    );

    this.encryptedDeks.set(kekId, encrypted.toString());
    return dek;
  }

  getDek(kekId: string): Buffer {
    if (!this.encryptedDeks.has(kekId)) {
      return this.generateDek(kekId);
    }

    const kek = this.keks.get(kekId);
    const encryptedDek = this.encryptedDeks.get(kekId);

    // Decrypt DEK using KEK
    const decrypted = CryptoJS.AES.decrypt(
      encryptedDek,
      kek.key.toString('hex'),
    );

    return Buffer.from(decrypted.toString(CryptoJS.enc.Utf8), 'hex');
  }

  rotateKek(oldKekId: string): string {
    // Generate new KEK ID
    const newKekId = Date.now().toString();
    this.deriveKek(newKekId);

    // If there was an old DEK, re-encrypt it with the new KEK
    if (this.encryptedDeks.has(oldKekId)) {
      const dek = this.getDek(oldKekId);
      const kek = this.keks.get(newKekId);

      const encrypted = CryptoJS.AES.encrypt(
        dek.toString('hex'),
        kek.key.toString('hex'),
      );

      this.encryptedDeks.set(newKekId, encrypted.toString());
      this.encryptedDeks.delete(oldKekId);
    }

    return newKekId;
  }
}
