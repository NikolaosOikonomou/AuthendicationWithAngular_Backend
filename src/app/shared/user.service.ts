import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { User } from './user.model';


@Injectable({
  providedIn: 'root'
})
export class UserService {
  readonly url = 'https://localhost:44361/';

  constructor(private http: HttpClient) { }

  registerUser(user: User, roles: string[]){
    const body = {
      UserName: user.UserName,
      Password: user.Password,
      Email: user.Email,
      FirstName: user.FirstName,
      LastName: user.LastName,
      Roles: roles
    }
    var reqHeader = new HttpHeaders({'No-Auth': 'True'});
    return this.http.post(this.url + '/api/User/Register', body, {headers: reqHeader});
  }

  userAuthentication(userName:string,password:string){
    var data = "username=" + userName + "&password=" + password + "&grant_type=password";
    var reqHeader = new HttpHeaders({ 'Content-Type': 'application/x-www-urlencoded','No-Auth':'True' });
    
    return this.http.post(this.url + '/token', data, { headers: reqHeader });
  }

  getUserClaims(){
   return this.http.get(this.url+'api/GetUserClaims');
  }

  getAllRoles() {
    var reqHeader = new HttpHeaders({ 'No-Auth': 'True' });
    return this.http.get(this.url + '/api/GetAllRoles', { headers: reqHeader });
  }

  roleMatch(allowedRoles:string[]): boolean {
    var isMatch = false;
    var userRoles:string[]=JSON.parse(localStorage.getItem('userRoles')|| 'null');
    allowedRoles.forEach((element:string) => {
      if(userRoles == null){
        return;
      }
      if (userRoles.indexOf(element) > -1) {
        isMatch = true;
        return;
      }
    });
    console.log("testing the return value of method roleMatch", isMatch);
    return isMatch;
  }
}
