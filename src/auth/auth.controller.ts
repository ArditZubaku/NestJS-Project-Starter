import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDTO } from './dto/signUp.dto';
import { SignInDTO } from './dto/signIn.dto';
import { GetCurrentUser } from 'src/common/decorators/get-current-user.decorator';
import { GetCurrentUserId } from 'src/common/decorators/get-current-user-id.decorator';
import { RtGuard } from 'src/common/guards/rt.guard';
import { Public } from 'src/common/decorators/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  signUp(@Body() dto: SignUpDTO) {
    return this.authService.signUp(dto);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('signin')
  signIn(@Body() dto: SignInDTO) {
    return this.authService.signIn(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('logout')
  logout(@GetCurrentUserId() userId: number) {
    return this.authService.logout(userId);
  }

  @Public() // Bypass the JwtGuard then execute the RtGuard
  @Post('refresh')
  @UseGuards(RtGuard)
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken')
    refreshToken: string,
  ) {
    return this.authService.refreshToken(userId, refreshToken);
  }
}
