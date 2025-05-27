import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as nodemailer from 'nodemailer';
import * as bcrypt from 'bcrypt';
import { Otp, OtpDocument } from './schemas/otp.schema';
import { SendOtpDto } from './dto/send-otp.dto';
import { LoginAdminDto } from './dto/login-admin.dto';
import { JwtService } from '@nestjs/jwt';
import { Admin, AdminDocument } from '../admin/schemas/admin.schema';
import { ResponseUtil } from '../common/utils/response.util';
import { ApiResponse } from '../common/interfaces/api-response.interface';

@Injectable()
export class AuthService {
  private transporter: nodemailer.Transporter;

  constructor(
    @InjectModel(Otp.name) private otpModel: Model<OtpDocument>,
    @InjectModel(Admin.name) private adminModel: Model<AdminDocument>,
    private jwtService: JwtService,
  ) {
    this.initializeEmailTransporter();
  }

  private initializeEmailTransporter() {
    try {
      this.transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });
      console.log('hehe');
    } catch (error) {
      console.error('Failed to initialize email transporter:', error);
    }
  }

  async login(
    dto: LoginAdminDto,
  ): Promise<ApiResponse<{ token: string; admin: Partial<AdminDocument> }>> {
    try {
      // Validate input
      if (!dto.email || !dto.password) {
        throw new BadRequestException('Email and password are required');
      }

      // Find admin
      const admin = await this.adminModel.findOne({
        email: dto.email.toLowerCase(),
      });
      if (!admin) {
        throw new UnauthorizedException('Invalid email or password');
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(
        dto.password,
        admin.password,
      );
      if (!isPasswordValid) {
        throw new UnauthorizedException('Invalid email or password');
      }

      // Generate JWT token
      const payload = {
        sub: admin._id.toString(),
        email: admin.email,
        role: 'admin',
      };

      const token = await this.jwtService.signAsync(payload);

      const adminData = {
        id: admin._id.toString(),
        firstname: admin.firstname,
        lastname: admin.lastname,
        email: admin.email,
      };

      return ResponseUtil.success('Login successful', {
        token,
        admin: adminData,
      });
    } catch (error) {
      if (
        error instanceof UnauthorizedException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }
      throw new InternalServerErrorException(
        'Login failed due to server error',
      );
    }
  }

  async sendOtp(
    dto: SendOtpDto,
  ): Promise<ApiResponse<{ email: string; expiresIn: string }>> {
    try {
      // Validate input
      if (!dto.email) {
        throw new BadRequestException('Email is required');
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(dto.email)) {
        throw new BadRequestException('Invalid email format');
      }

      // Check if email service is configured
      if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        throw new ServiceUnavailableException(
          'Email service is not configured',
        );
      }

      // Generate OTP
      const otp = this.generateOTP();
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + 10); // 10 minutes expiry

      // Clean up old OTPs for this email
      await this.otpModel.deleteMany({ email: dto.email.toLowerCase() });

      // Create new OTP record
      await this.otpModel.create({
        email: dto.email.toLowerCase(),
        otp,
        expiresAt,
      });

      // Send email
      await this.sendEmail(dto.email, otp);

      return ResponseUtil.success('OTP sent successfully', {
        email: dto.email.toLowerCase(),
        expiresIn: '10 minutes',
      });
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof ServiceUnavailableException
      ) {
        throw error;
      }

      // Handle specific email sending errors
      if (error.code === 'EAUTH' || error.code === 'ENOTFOUND') {
        throw new ServiceUnavailableException(
          'Email service is temporarily unavailable',
        );
      }

      throw new InternalServerErrorException('Failed to send OTP');
    }
  }

  async verifyOtp(
    email: string,
    otp: string,
  ): Promise<ApiResponse<{ isValid: boolean }>> {
    try {
      if (!email || !otp) {
        throw new BadRequestException('Email and OTP are required');
      }

      const otpRecord = await this.otpModel.findOne({
        email: email.toLowerCase(),
        otp: otp.trim(),
      });

      if (!otpRecord) {
        throw new UnauthorizedException('Invalid OTP');
      }

      if (new Date() > otpRecord.expiresAt) {
        // Clean up expired OTP
        await this.otpModel.deleteOne({ _id: otpRecord._id });
        throw new UnauthorizedException('OTP has expired');
      }

      return ResponseUtil.success('OTP verified successfully', {
        isValid: true,
      });
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException
      ) {
        throw error;
      }
      throw new InternalServerErrorException('OTP verification failed');
    }
  }

  async resendOtp(
    email: string,
  ): Promise<ApiResponse<{ email: string; expiresIn: string }>> {
    try {
      const recentOtp = await this.otpModel.findOne({
        email: email.toLowerCase(),
        createdAt: { $gt: new Date(Date.now() - 60000) }, // 1 minute ago
      });

      if (recentOtp) {
        throw new BadRequestException(
          'Please wait before requesting another OTP',
        );
      }

      return this.sendOtp({ email });
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to resend OTP');
    }
  }

  async logout(): Promise<ApiResponse<null>> {
    try {
      // In a stateless JWT setup, logout is typically handled client-side
      // You might want to implement token blacklisting here if needed
      return ResponseUtil.success('Logged out successfully', null);
    } catch (error) {
      throw new InternalServerErrorException('Logout failed');
    }
  }

  // Utility Methods
  private generateOTP(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  private async sendEmail(email: string, otp: string): Promise<void> {
    try {
      if (!this.transporter) {
        throw new Error('Email transporter not initialized');
      }

      const mailOptions = {
        from: {
          name: 'Admin Portal',
          address: process.env.EMAIL_USER,
        },
        to: email,
        subject: '🔐 Your OTP Verification Code',
        text: `Your OTP code is: ${otp}. This code will expire in 10 minutes.`,
        html: this.generateEmailTemplate(otp),
      };

      await this.transporter.sendMail(mailOptions);
    } catch (error) {
      console.error('Email sending failed:', error);
      throw new ServiceUnavailableException(
        'Email service is temporarily unavailable',
      );
    }
  }

  private generateEmailTemplate(otp: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OTP Verification</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
          
          <!-- Header -->
          <div style="text-align: center; padding: 20px 0; border-bottom: 2px solid #e9ecef;">
            <h1 style="color: #333; margin: 0; font-size: 24px;">🔐 Verification Code</h1>
          </div>
          
          <!-- Content -->
          <div style="padding: 30px 0; text-align: center;">
            <p style="color: #666; font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
              Here's your one-time verification code:
            </p>
            
            <!-- OTP Code Box -->
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; display: inline-block; margin: 20px 0;">
              <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                ${otp}
              </div>
            </div>
            
            <p style="color: #666; font-size: 14px; line-height: 1.6; margin-top: 30px;">
              This code will expire in <strong>10 minutes</strong>.<br>
              If you didn't request this code, please ignore this email.
            </p>
          </div>
          
          <!-- Footer -->
          <div style="border-top: 1px solid #e9ecef; padding-top: 20px; text-align: center;">
            <p style="color: #999; font-size: 12px; margin: 0;">
              This is an automated message, please do not reply to this email.
            </p>
          </div>
          
        </div>
      </body>
      </html>
    `;
  }

  // Health check method for email service
  async checkEmailService(): Promise<ApiResponse<{ isHealthy: boolean }>> {
    try {
      if (!this.transporter) {
        return ResponseUtil.error('Email service not configured');
      }

      await this.transporter.verify();
      return ResponseUtil.success('Email service is healthy', {
        isHealthy: true,
      });
    } catch (error) {
      return ResponseUtil.error('Email service is unhealthy');
    }
  }
}
