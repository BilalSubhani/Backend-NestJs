import { Controller, Get, Post, Body, ValidationPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SendOtpDto } from './dto/send-otp.dto';
import { LoginAdminDto } from './dto/login-admin.dto';

@Controller('v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(@Body(ValidationPipe) dto: LoginAdminDto) {
    return this.authService.login(dto);
  }

  @Post('send-otp')
  async sendOtp(@Body(ValidationPipe) dto: SendOtpDto) {
    return this.authService.sendOtp(dto);
  }

  @Post('verify-otp')
  async verifyOtp(@Body(ValidationPipe) body: { email: string; otp: string }) {
    return this.authService.verifyOtp(body.email, body.otp);
  }

  @Post('resend-otp')
  async resendOtp(@Body(ValidationPipe) body: { email: string }) {
    return this.authService.resendOtp(body.email);
  }

  @Post('logout')
  async logout() {
    return this.authService.logout();
  }

  @Get('health/email')
  async checkEmailHealth() {
    return this.authService.checkEmailService();
  }
}
