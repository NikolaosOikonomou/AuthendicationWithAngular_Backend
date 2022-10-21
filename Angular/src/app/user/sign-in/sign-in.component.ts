import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { UserService } from 'src/app/shared/user.service';

@Component({
  selector: 'app-sign-in',
  templateUrl: './sign-in.component.html',
  styleUrls: ['./sign-in.component.css']
})
export class SignInComponent implements OnInit {

  isLoginError: boolean = false;
  constructor(private userService: UserService, private router: Router) { }

  ngOnInit(): void {
  }

  OnSubmit(userName:string, password:string){
    this.userService.userAuthentication(userName,password).subscribe({
      next: (data:any) => 
      {
        console.log(data),
        localStorage.setItem('userToken',data.access_token),
        localStorage.setItem('userRoles',data.role),
        this.router.navigate(['/home']);
      },
      error: error => {console.log(error), this.isLoginError = true},
      complete: () => console.log("Sign In Done")
    });
  }
}
