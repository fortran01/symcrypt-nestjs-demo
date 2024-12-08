import { Module } from '@nestjs/common';
import { KeyManagerService } from './key-manager.service';
import { AWSKeyManagerService } from './aws-key-manager.service';
import { EncryptionController } from './encryption.controller';

@Module({
  controllers: [EncryptionController],
  providers: [KeyManagerService, AWSKeyManagerService],
})
export class EncryptionModule {}
