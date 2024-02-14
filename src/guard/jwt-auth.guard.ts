import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  // Esta clase extiende AuthGuard y utiliza la estrategia 'jwt'
  canActivate(context: ExecutionContext) {
    // Puedes realizar acciones de autorización personalizadas aquí si es necesario
    // Por ejemplo, verificar roles o permisos adicionales
    return super.canActivate(context);
  }

  handleRequest(err, user) {
    // Puedes personalizar la respuesta en caso de error de autenticación
    if (err || !user) {
      throw err || new UnauthorizedException();
    }
    return user;
  }
}
