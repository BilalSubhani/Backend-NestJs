import {
  BadRequestException,
  Injectable,
  NotFoundException,
  ConflictException,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Admin, AdminDocument } from './schemas/admin.schema';
import { Model } from 'mongoose';
import { RegisterAdminDto } from './dto/register-admin.dto';
import { UpdateAdminDto } from './dto/update-admin.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import * as bcrypt from 'bcrypt';
import { Otp, OtpDocument } from '../auth/schemas/otp.schema';
import { ResponseUtil } from '../common/utils/response.util';
import { ApiResponse } from '../common/interfaces/api-response.interface';

@Injectable()
export class AdminService {
  constructor(
    @InjectModel(Admin.name) private adminModel: Model<AdminDocument>,
    @InjectModel(Otp.name) private otpModel: Model<OtpDocument>,
  ) {}

  async register(
    dto: RegisterAdminDto,
  ): Promise<ApiResponse<{ id: string; email: string }>> {
    try {
      const existingAdmin = await this.adminModel.findOne({ email: dto.email });
      if (existingAdmin) {
        throw new ConflictException('Admin with this email already exists');
      }

      const otpRecord = await this.otpModel.findOne({ email: dto.email });
      if (!otpRecord) {
        throw new BadRequestException('OTP not found for this email');
      }

      if (otpRecord.otp !== dto.otp) {
        throw new BadRequestException('Invalid OTP provided');
      }

      if (new Date() > otpRecord.expiresAt) {
        throw new BadRequestException('OTP has expired');
      }

      const hashedPassword = await bcrypt.hash(dto.password, 10);
      const hashedSecQ = await bcrypt.hash(dto.securityQuestion, 10);

      const admin = await this.adminModel.create({
        firstname: dto.firstname,
        lastname: dto.lastname,
        email: dto.email,
        password: hashedPassword,
        securityQuestion: hashedSecQ,
      });

      await this.otpModel.deleteMany({ email: dto.email });

      return ResponseUtil.success('Admin registered successfully', {
        id: admin._id.toString(),
        email: admin.email,
      });
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof ConflictException
      ) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to register admin');
    }
  }

  async fetch(id: string): Promise<ApiResponse<AdminDocument>> {
    try {
      if (!id || !id.match(/^[0-9a-fA-F]{24}$/)) {
        throw new BadRequestException('Invalid admin ID format');
      }

      const admin = await this.adminModel
        .findById(id)
        .select('-password -securityQuestion');

      if (!admin) {
        throw new NotFoundException('Admin not found');
      }

      return ResponseUtil.success('Admin retrieved successfully', admin);
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof NotFoundException
      ) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to fetch admin');
    }
  }

  async fetchAll(): Promise<ApiResponse<AdminDocument[]>> {
    try {
      const admins = await this.adminModel
        .find()
        .select('-password -securityQuestion')
        .sort({ createdAt: -1 });

      return ResponseUtil.success(
        admins.length > 0 ? 'Admins retrieved successfully' : 'No admins found',
        admins,
      );
    } catch (error) {
      throw new InternalServerErrorException('Failed to fetch admins');
    }
  }

  async update(
    id: string,
    dto: UpdateAdminDto,
  ): Promise<ApiResponse<AdminDocument>> {
    try {
      if (!id || !id.match(/^[0-9a-fA-F]{24}$/)) {
        throw new BadRequestException('Invalid admin ID format');
      }

      if (dto.email) {
        const existingAdmin = await this.adminModel.findOne({
          email: dto.email,
          _id: { $ne: id },
        });
        if (existingAdmin) {
          throw new ConflictException('Email already exists for another admin');
        }
      }

      const updated = await this.adminModel
        .findByIdAndUpdate(id, dto, { new: true })
        .select('-password -securityQuestion');

      if (!updated) {
        throw new NotFoundException('Admin not found');
      }

      return ResponseUtil.success('Admin updated successfully', updated);
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof NotFoundException ||
        error instanceof ConflictException
      ) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to update admin');
    }
  }

  async delete(id: string): Promise<ApiResponse<null>> {
    try {
      if (!id || !id.match(/^[0-9a-fA-F]{24}$/)) {
        throw new BadRequestException('Invalid admin ID format');
      }

      const result = await this.adminModel.findByIdAndDelete(id);

      if (!result) {
        throw new NotFoundException('Admin not found');
      }

      return ResponseUtil.success('Admin deleted successfully', null);
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof NotFoundException
      ) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to delete admin');
    }
  }

  async resetPassword(dto: ResetPasswordDto): Promise<ApiResponse<null>> {
    try {
      const otpRecord = await this.otpModel.findOne({ email: dto.email });
      if (!otpRecord) {
        throw new BadRequestException('OTP not found for this email');
      }

      if (otpRecord.otp !== dto.otp) {
        throw new BadRequestException('Invalid OTP provided');
      }

      if (new Date() > otpRecord.expiresAt) {
        throw new BadRequestException('OTP has expired');
      }

      const admin = await this.adminModel.findOne({ email: dto.email });
      if (!admin) {
        throw new NotFoundException('Admin not found with this email');
      }

      const isSecQMatch = await bcrypt.compare(
        dto.securityQuestion,
        admin.securityQuestion,
      );
      if (!isSecQMatch) {
        throw new BadRequestException('Security question answer is incorrect');
      }

      const hashedPassword = await bcrypt.hash(dto.newPassword, 10);
      admin.password = hashedPassword;
      await admin.save();

      await this.otpModel.deleteMany({ email: dto.email });

      return ResponseUtil.success('Password reset successfully', null);
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof NotFoundException
      ) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to reset password');
    }
  }

  async checkAdminExists(email: string): Promise<boolean> {
    try {
      const admin = await this.adminModel.findOne({ email });
      return !!admin;
    } catch (error) {
      throw new InternalServerErrorException('Failed to check admin existence');
    }
  }
}
