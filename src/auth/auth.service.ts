import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import * as argon from 'argon2';

import { AuthDto } from './dto';
import { JWT_AT_KEY } from 'src/common/types';

@Injectable()
export class AuthService {
  constructor(
    private config: ConfigService,
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signup(dto: AuthDto) {
    const hash = await argon.hash(dto.password);

    try {
      const user = await this.prismaService.user.create({
        data: { email: dto.email, hash },
      });

      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }

      throw error;
    }
  }

  async signin(dto: AuthDto) {
    const forbiddenError = new ForbiddenException('Credentials incorrect');
    const user = await this.prismaService.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw forbiddenError;
    }

    const passMatches = await argon.verify(user.hash, dto.password);

    if (!passMatches) {
      throw forbiddenError;
    }

    return this.signToken(user.id, user.email);
  }

  async signToken(userId: number, email: string): Promise<object> {
    const payload = {
      sub: userId,
      email,
    };
    const access_token = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get(JWT_AT_KEY),
    });
    return { access_token };
  }
}
