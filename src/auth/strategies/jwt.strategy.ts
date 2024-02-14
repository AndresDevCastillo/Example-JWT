import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { PassportStrategy } from '@nestjs/passport';
import { Model } from 'mongoose';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from '../interfaces/jwt-strategy.interface';
import * as bcrypt from 'bcrypt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    // Injecta el modelo de usuario
    @Inject(JwtService) private jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    super({
      secretOrKey: configService.get<string>('SECRET'),
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    });
  }
  async validate(
    payload: JwtPayload,
  ): Promise<Usuario | { access_token: string }> {
    const { user } = payload;
    const userBd = await this.usuarioModel.find({ // remplaza por tus funciones de busqueda de usuario
      usuario: user,
    });
    if (userBd.length == 0) {
      throw new UnauthorizedException('El usuario no esta registrado');
    }
    const payloadZ = {
      sub: userBd[0]._id,
      usuario: userBd[0].usuario,
    };
    return {
      ...userBd,
      access_token: await this.jwtService.signAsync(payloadZ),
    };
  }

  async loginJwt(payload: JwtPayload): Promise<any> {
    const { user, password } = payload;

    const userBd = await this.usuarioModel
      .find({
        usuario: user,
      })
      .select([
        '_id',
        'usuario',
        'correo',
        'telefono',
        'rol',
      ]);

    if (userBd.length == 0) {
      throw new UnauthorizedException('El usuario no esta registrado');
    } else if (!bcrypt.compareSync(password, userBd[0].contrasena)) {
      throw new UnauthorizedException('La contraseña es incorrecta');
    }
    const payloadZ = {
      sub: userBd[0]._id,
      user: userBd[0].usuario,
      rol: userBd[0].rol,
    };
    delete userBd[0].contrasena;
    const userReturn = {
      _id: userBd[0]._id,
      usuario: userBd[0].usuario,
      correo: userBd[0].correo,
      telefono: userBd[0].telefono,
      rol: userBd[0].rol,
      access_token: await this.jwtService.signAsync(payloadZ),
    };
    return userReturn;
  }
}
