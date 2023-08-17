import { PrismaService } from '../../prisma/prisma.service';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';

// import { Strategy } from "passport-local";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    config: ConfigService,
    private readonly prismaService: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get('JWT_SECRET'),
    });
  }

  async validate(payload: { sub: number }) {
    // Attaches the payload to the req.user object
    const user = await this.prismaService.user.findUnique({
      where: {
        id: payload.sub,
      },
    });
    delete user.password;
    return user;
  }
}
