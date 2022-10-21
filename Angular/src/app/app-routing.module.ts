import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AdminPanelComponent } from './admin-panel/admin-panel.component';
import { AuthGuard } from './auth/auth.guard';
import { ForbiddenComponent } from './forbidden/forbidden.component';
import { HomeComponent } from './home/home.component'
import { SignInComponent } from './user/sign-in/sign-in.component';
import { SignUpComponent } from './user/sign-up/sign-up.component';
import { UserComponent } from './user/user.component';

const routes: Routes = [
  {path: 'home', component : HomeComponent, canActivate:[AuthGuard]},
  {path: 'forbidden', component : ForbiddenComponent, canActivate:[AuthGuard]},
  { path: 'adminPanel', component: AdminPanelComponent, canActivate: [AuthGuard] , data: { roles: ['Admin'] }},
  {
    path: 'signup', component : UserComponent,
    children : [{path: '', component: SignUpComponent}]
  },
  {
    path: 'login', component : UserComponent,
    children : [{path: '', component: SignInComponent}]
  },
  {path: '', redirectTo:'/login', pathMatch: 'full'} //Default routing
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
