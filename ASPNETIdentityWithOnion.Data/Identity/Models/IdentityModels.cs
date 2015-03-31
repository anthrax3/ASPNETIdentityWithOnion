using Microsoft.AspNet.Identity.EntityFramework;
using System;

namespace ASPNETIdentityWithOnion.Data.Identity.Models
{
    // You can add profile data for the user by adding more properties to your ApplicationIdentityUser class, please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationIdentityUser :
        IdentityUser<string, ApplicationIdentityUserLogin, ApplicationIdentityUserRole, ApplicationIdentityUserClaim>
    {
        public ApplicationIdentityUser()
        {
            this.Id = Guid.NewGuid().ToString();
        }
    }


    public class ApplicationIdentityRole : IdentityRole<string, ApplicationIdentityUserRole>
    {
        public ApplicationIdentityRole()
        {
            this.Id = Guid.NewGuid().ToString();
        }

        public ApplicationIdentityRole(string name)
            : this()
        {
            Name = name;
        }
    }

    public class ApplicationIdentityUserRole : IdentityUserRole<string>
    {
    }

    public class ApplicationIdentityUserClaim : IdentityUserClaim<string>
    {
    }

    public class ApplicationIdentityUserLogin : IdentityUserLogin<string>
    {
    }

}