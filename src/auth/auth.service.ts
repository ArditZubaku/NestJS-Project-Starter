import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { Prisma } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { SignUpDTO } from './dto/signUp.dto';
import { SignInDTO } from './dto/signIn.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}

  async signUp(dto: SignUpDTO) {
    try {
      const { password, ...others } = dto;

      //Generate the hashed password
      const hashedPassword = await argon.hash(password);

      const user = await this.prismaService.user.create({
        data: {
          password: hashedPassword,
          ...others,
        },
      });

      const tokens = await this.getTokens(user.id, user.email);
      await this.updateRefreshTokenHash(user.id, tokens.refreshToken);

      delete user.password;

      return { user, tokens };
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ForbiddenException(
          'Try another email, an user with this email already exists!',
        );
      }
      throw error;
    }
  }

  async signIn(dto: SignInDTO) {
    try {
      const { email, password } = dto;
      // Find the user by email
      const user = await this.prismaService.user.findUnique({
        where: {
          email,
        },
      });
      if (!user) {
        throw new ForbiddenException('No user with this email exists!');
      }

      // Compare passwords
      const matchingPassword: boolean = await argon.verify(
        user.password,
        password,
      );
      if (!matchingPassword) {
        throw new ForbiddenException('Incorrect password!');
      }

      const tokens = await this.getTokens(user.id, user.email);
      await this.updateRefreshTokenHash(user.id, tokens.refreshToken);

      delete user.password;

      return { user, tokens };
    } catch (error) {
      throw error;
    }
  }

  logout(userId: number) {
    try {
      this.prismaService.user.update({
        where: {
          id: userId,
          hashedRefreshToken: {
            not: null,
          },
        },
        data: {
          hashedRefreshToken: null,
        },
      });
      return { message: 'Successfully logged out.' };
    } catch (error) {
      throw error;
    }
  }

  async refreshToken(userId: number, refreshToken: string) {
    const user = await this.prismaService.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user) throw new ForbiddenException('Access denied!');

    const refreshTokenMatches: boolean = await argon.verify(
      user.hashedRefreshToken,
      refreshToken,
    );

    if (!refreshTokenMatches) throw new ForbiddenException('Access denied!');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refreshToken);

    return tokens;
  }

  async updateRefreshTokenHash(
    userId: number,
    refreshToken: string,
  ): Promise<void> {
    const hash: string = await argon.hash(refreshToken);

    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRefreshToken: hash,
      },
    });
  }

  async getTokens(userId: number, email: string) {
    const [at, rt] = await Promise.all([
      // Access token
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: this.config.get('JWT_SECRET'),
          expiresIn: 60 * 15,
        },
      ),
      // Refresh token
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: this.config.get('JWT_REFRESH_SECRET'),
          expiresIn: 60 * 60 * 24 * 7,
        },
      ),
    ]);

    return {
      accessToken: at,
      refreshToken: rt,
    };
  }
}
