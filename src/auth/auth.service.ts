import { Inject, Injectable } from '@nestjs/common';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LoginDto } from 'src/usuario/dto/create-usuario.dto';

@Injectable()
export class AuthService {
  constructor(@Inject(JwtStrategy) private jwtStrategy: JwtStrategy) {}
  async signIn(userSignIn: LoginDto) {
    return await this.jwtStrategy.loginJwt(userSignIn);
  }
}
