import { Injectable, Logger } from '@nestjs/common';
import {
  KMSClient,
  GenerateDataKeyCommand,
  DecryptCommand,
} from '@aws-sdk/client-kms';
import * as CryptoJS from 'crypto-js';

@Injectable()
export class AWSKeyManagerService {
  private readonly kmsClient: KMSClient;
  private readonly logger = new Logger(AWSKeyManagerService.name);
  private readonly masterKeyId: string;

  constructor() {
    this.kmsClient = new KMSClient({});
    this.masterKeyId = process.env.AWS_KMS_KEY_ID;
    this.logger.log(`Initialized with master key ID: ${this.masterKeyId}`);
  }

  async createDataKey(): Promise<{
    encrypted: Buffer;
    plaintext: Buffer;
    keyId: string;
  }> {
    try {
      this.logger.debug('Attempting to generate new data key from AWS KMS');
      
      const command = new GenerateDataKeyCommand({
        KeyId: this.masterKeyId,
        KeySpec: 'AES_256',
      });

      const response = await this.kmsClient.send(command);
      this.logger.debug('Successfully generated data key');

      // Extract key ID from ARN
      const keyId = response.KeyId.split('/').pop().slice(0, 8);

      return {
        encrypted: Buffer.from(response.CiphertextBlob),
        plaintext: Buffer.from(response.Plaintext),
        keyId,
      };
    } catch (error) {
      this.logger.error(`Error in createDataKey: ${error.message}`);
      throw error;
    }
  }

  async decryptDataKey(encryptedDataKey: Buffer): Promise<Buffer> {
    try {
      this.logger.debug('Attempting to decrypt data key using AWS KMS');
      
      const command = new DecryptCommand({
        KeyId: this.masterKeyId,
        CiphertextBlob: encryptedDataKey,
      });

      const response = await this.kmsClient.send(command);
      this.logger.debug('Successfully decrypted data key');

      return Buffer.from(response.Plaintext);
    } catch (error) {
      this.logger.error(`Error in decryptDataKey: ${error.message}`);
      throw error;
    }
  }

  async encryptData(data: string): Promise<{
    encryptedData: string;
    encryptedDataKey: Buffer;
    keyId: string;
  }> {
    try {
      this.logger.debug('Starting encryption process for data');
      
      // Generate a new data key
      const dataKey = await this.createDataKey();
      this.logger.debug('Successfully created new data key');

      // Use the plaintext data key to encrypt the data
      const encrypted = CryptoJS.AES.encrypt(
        data,
        dataKey.plaintext.toString('hex'),
      );

      this.logger.debug('Successfully encrypted data with data key');

      return {
        encryptedData: encrypted.toString(),
        encryptedDataKey: dataKey.encrypted,
        keyId: dataKey.keyId,
      };
    } catch (error) {
      this.logger.error(`Error in encryptData: ${error.message}`);
      throw error;
    }
  }

  async decryptData(
    encryptedData: string,
    encryptedDataKey: Buffer,
  ): Promise<string> {
    try {
      this.logger.debug('Starting decryption process');
      
      // First decrypt the data key
      const plaintextKey = await this.decryptDataKey(encryptedDataKey);
      this.logger.debug('Successfully decrypted data key');

      // Use the plaintext key to decrypt the data
      const decrypted = CryptoJS.AES.decrypt(
        encryptedData,
        plaintextKey.toString('hex'),
      );

      this.logger.debug('Successfully decrypted data');

      return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      this.logger.error(`Error in decryptData: ${error.message}`);
      throw error;
    }
  }
}
