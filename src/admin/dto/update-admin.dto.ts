// src/admin/dto/update-admin.dto.ts
import { IsOptional, IsEmail } from 'class-validator';

export class UpdateAdminDto {
  @IsOptional()
  firstname?: string;

  @IsOptional()
  lastname?: string;

  @IsOptional()
  @IsEmail()
  email?: string;
}
