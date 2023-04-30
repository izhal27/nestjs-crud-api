import { Controller, Get, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { CurrentUser } from '../common/decorators';
import { JwtGuard } from 'src/common/guards';

@Controller('users')
export class UsersController {
  constructor(private userService: UsersService) {}

  @UseGuards(JwtGuard)
  @Get('current')
  getCurrentUser(@CurrentUser('sub') userId: number) {
    return this.userService.getCurrentUser(userId);
  }
}
