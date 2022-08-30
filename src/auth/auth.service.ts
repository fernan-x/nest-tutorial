import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(authDto: AuthDto) {
    // Generate pass hash
    const hashedPassword = await argon.hash(authDto.password);

    // Save the new user in db
    try {
      const user = await this.prisma.user.create({
        data: {
          email: authDto.email,
          password: hashedPassword,
        },
      });

      // TODO : remove this part to transform request
      delete user.password;

      // Return the new user
      return user;
    } catch (error) {
      // Handle duplicate entries
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Email already exists');
        }
      }

      throw error;
    }
  }

  async signin(authDto: AuthDto) {
    // Find the user
    const user = await this.prisma.user.findUnique({
      where: {
        email: authDto.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }

    // Compare password
    const pwMatches = await argon.verify(user.password, authDto.password);
    if (!pwMatches) {
      throw new ForbiddenException('Credentials incorrect');
    }

    // TODO : remove this part to transform request
    delete user.password;

    // Return the new user
    return user;
  }
}
