import { HttpInterceptor, HttpRequest, HttpHandler, HttpUserEvent, HttpEvent } from "@angular/common/http";
import { catchError, Observable } from "rxjs";
import { UserService } from "../shared/user.service";
import { Injectable } from "@angular/core";
import { Router } from "@angular/router";

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

    constructor(private router: Router) { }

    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
      
      if (req.headers.get('No-Auth') == "True")
         return next.handle(req.clone());
      
      if (localStorage.getItem('userToken') != null) {
          const clonedreq = req.clone({
          headers: req.headers.set("Authorization", "Bearer " + localStorage.getItem('userToken'))          
      });
      console.log("Interceptor");
      return next.handle(clonedreq)
          .pipe( 
               catchError(err => 
                {
                  if (err.status === 401)
                  this.router.navigateByUrl('/SignIn');
                  throw 'error in source. Details: ' + err;
                } 
          ))
  }
  else {
      this.router.navigateByUrl('/SignIn');
  }
  throw new Error("Intercept error from last line, (throw)");
    }
}