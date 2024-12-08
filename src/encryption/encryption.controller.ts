import {
  Controller,
  Post,
  Body,
  Get,
  Session,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { KeyManagerService } from './key-manager.service';
import { AWSKeyManagerService } from './aws-key-manager.service';
import * as CryptoJS from 'crypto-js';

@Controller('encryption')
export class EncryptionController {
  constructor(
    private readonly keyManagerService: KeyManagerService,
    private readonly awsKeyManagerService: AWSKeyManagerService,
  ) {}

  @Post('create-session')
  async createSession(
    @Body() body: { userData: string },
    @Session() session: Record<string, any>,
  ) {
    try {
      const kekId = Date.now().toString();
      const dek = this.keyManagerService.getDek(kekId);

      // Encrypt the user data
      const encrypted = CryptoJS.AES.encrypt(
        body.userData,
        dek.toString('hex'),
      );

      session.kekId = kekId;
      session.encryptedData = encrypted.toString();

      return {
        message: 'Session created',
        kekId,
      };
    } catch (error) {
      throw new HttpException(
        'Failed to create session',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('get-session')
  async getSession(@Session() session: Record<string, any>) {
    if (!session.kekId) {
      throw new HttpException('No session found', HttpStatus.NOT_FOUND);
    }

    try {
      const dek = this.keyManagerService.getDek(session.kekId);
      const decrypted = CryptoJS.AES.decrypt(
        session.encryptedData,
        dek.toString('hex'),
      );

      return {
        data: decrypted.toString(CryptoJS.enc.Utf8),
        kekId: session.kekId,
      };
    } catch (error) {
      throw new HttpException(
        'Failed to decrypt session data',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('rotate-kek')
  async rotateKek(@Session() session: Record<string, any>) {
    if (!session.kekId) {
      throw new HttpException('No session found', HttpStatus.NOT_FOUND);
    }

    try {
      const oldKekId = session.kekId;
      const oldDek = this.keyManagerService.getDek(oldKekId);
      
      // First decrypt the data with the old DEK
      const decryptedBytes = CryptoJS.AES.decrypt(
        session.encryptedData,
        oldDek.toString('hex'),
      );
      const decryptedData = decryptedBytes.toString(CryptoJS.enc.Utf8);
      
      // Rotate the KEK and get a new DEK
      const newKekId = this.keyManagerService.rotateKek(oldKekId);
      const newDek = this.keyManagerService.getDek(newKekId);

      // Re-encrypt the data with the new DEK
      const reEncrypted = CryptoJS.AES.encrypt(
        decryptedData,
        newDek.toString('hex'),
      );

      session.kekId = newKekId;
      session.encryptedData = reEncrypted.toString();

      return {
        message: 'KEK rotated successfully',
        oldKekId,
        newKekId,
      };
    } catch (error) {
      throw new HttpException(
        'Failed to rotate KEK',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // AWS KMS endpoints
  @Post('aws/encrypt')
  async awsEncrypt(@Body() body: { data: string }) {
    try {
      const result = await this.awsKeyManagerService.encryptData(body.data);
      return {
        encryptedData: result.encryptedData,
        encryptedDataKey: result.encryptedDataKey.toString('base64'),
        keyId: result.keyId,
      };
    } catch (error) {
      throw new HttpException(
        'Failed to encrypt data using AWS KMS',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('aws/decrypt')
  async awsDecrypt(
    @Body() body: { encryptedData: string; encryptedDataKey: string },
  ) {
    try {
      const decrypted = await this.awsKeyManagerService.decryptData(
        body.encryptedData,
        Buffer.from(body.encryptedDataKey, 'base64'),
      );
      return { decryptedData: decrypted };
    } catch (error) {
      throw new HttpException(
        'Failed to decrypt data using AWS KMS',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
