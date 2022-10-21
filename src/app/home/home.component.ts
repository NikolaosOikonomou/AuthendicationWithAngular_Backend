import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { UserService } from '../shared/user.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {
  userClaims:any;

  constructor(private router: Router, public userService: UserService) { }

  ngOnInit(): void {
    this.UserData();
  }

  Logout(){
    localStorage.removeItem('userToken');
    this.router.navigate(['/login']);
  }

  UserData(){
    this.userService.getUserClaims().subscribe({
      next: (data:any) => {this.userClaims = data, console.log(data)},
      error: error => console.log(error),
      complete: () => console.log("User claims Done")
    });
  }

}
