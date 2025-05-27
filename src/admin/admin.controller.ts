// src/admin/admin.controller.ts
import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  ValidationPipe,
  UseGuards,
} from '@nestjs/common';
import { AdminService } from './admin.service';
import { RegisterAdminDto } from './dto/register-admin.dto';
import { UpdateAdminDto } from './dto/update-admin.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Controller('v1/admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @Post('register')
  async register(@Body(ValidationPipe) dto: RegisterAdminDto) {
    return this.adminService.register(dto);
  }

  @Get(':id')
  async fetch(@Param('id') id: string) {
    return this.adminService.fetch(id);
  }

  @Get()
  async fetchAll() {
    return this.adminService.fetchAll();
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateAdminDto,
  ) {
    return this.adminService.update(id, dto);
  }

  @Delete(':id')
  async delete(@Param('id') id: string) {
    return this.adminService.delete(id);
  }

  @Post('reset-password')
  async resetPassword(@Body(ValidationPipe) dto: ResetPasswordDto) {
    return this.adminService.resetPassword(dto);
  }
}
