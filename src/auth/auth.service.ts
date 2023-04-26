import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';

import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import * as argon from 'argon2';

import { AuthDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
  ) {}

  async signup(dto: AuthDto) {
    const hash = await argon.hash(dto.password);

    try {
      const user =
        await this.prismaService.user.create({
          data: { email: dto.email, hash },
        });

      delete user.hash;
      return user;
    } catch (error) {
      if (
        error instanceof
        Prisma.PrismaClientKnownRequestError
      ) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'Credentials taken',
          );
        }
      }

      throw error;
    }
  }

  async signin(dto: AuthDto) {
    const forbiddenError = new ForbiddenException(
      'Credentials incorrect',
    );
    const user =
      await this.prismaService.user.findUnique({
        where: {
          email: dto.email,
        },
      });

    if (!user) {
      throw forbiddenError;
    }

    const passMatches = await argon.verify(
      user.hash,
      dto.password,
    );

    if (!passMatches) {
      throw forbiddenError;
    }

    delete user.hash;
    return user;
  }
}
