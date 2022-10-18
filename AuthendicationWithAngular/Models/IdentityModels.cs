using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AuthendicationWithAngular.Models
{
    public class IdentityModels: IdentityUser
    {
        public string FirstName { get; set; }

        public string LastName { get; set; }
    }

    public class ApplicationDbContext: IdentityDbContext<IdentityModels>
    {
        public ApplicationDbContext(): base("Sindesmos")
        {

        }
    }
}