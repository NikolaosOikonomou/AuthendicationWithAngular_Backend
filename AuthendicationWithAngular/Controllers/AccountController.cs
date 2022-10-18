using AuthendicationWithAngular.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Cors;

namespace AuthendicationWithAngular.Controllers
{
    [EnableCors("*", "*", "GET,POST,PUT,DELETE")]
    public class AccountController : ApiController
    {
        [Route("api/User/Register")]
        [HttpPost]
        public IdentityResult Register(AccountModel model)
        {
            var userStore = new UserStore<IdentityModels>(new ApplicationDbContext());
            var manager = new UserManager<IdentityModels>(userStore);
            var user = new IdentityModels() { UserName = model.UserName, Email = model.Email };
            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 3
            };
            IdentityResult result = manager.Create(user, model.Password);

            return result;
        }
    }
}
