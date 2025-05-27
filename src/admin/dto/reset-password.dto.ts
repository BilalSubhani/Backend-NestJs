// src/admin/dto/reset-password.dto.ts
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  otp: string;

  @IsNotEmpty()
  securityQuestion: string;

  @MinLength(6)
  newPassword: string;
}
