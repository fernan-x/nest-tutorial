import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(authDto: AuthDto): Promise<{ access_token: string }> {
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

      // Return the jwt
      return this.generateJWT(user.id, user.email);
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

  async signin(authDto: AuthDto): Promise<{ access_token: string }> {
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

    // Return the jwt
    return this.generateJWT(user.id, user.email);
  }

  /**
   * Get a JWT based on user Id and user email
   * @param     number  userId        User id
   * @param     string  email         User email
   * @returns                         Json web token value
   */
  async generateJWT(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET'),
    });

    return { access_token: token };
  }
}
