// src/admin/dto/register-admin.dto.ts
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class RegisterAdminDto {
  @IsNotEmpty()
  firstname: string;

  @IsNotEmpty()
  lastname: string;

  @IsEmail()
  email: string;

  @MinLength(6)
  password: string;

  @IsNotEmpty()
  securityQuestion: string;

  @IsNotEmpty()
  otp: string;
}
