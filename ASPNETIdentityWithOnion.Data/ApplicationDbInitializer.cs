using System;
using System.Data.Entity;
using ASPNETIdentityWithOnion.Core.DomainModels;
using ASPNETIdentityWithOnion.Core.Logging;
using ASPNETIdentityWithOnion.Data.Identity;
using ASPNETIdentityWithOnion.Data.Identity.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

namespace ASPNETIdentityWithOnion.Data
{
    // This is useful if you do not want to tear down the database each time you run the application.
    // public class ApplicationDbInitializer : DropCreateDatabaseAlways<ApplicationDbContext>
    // This example shows you how to create a new database if the Model changes
    public class ApplicationDbInitializer : DropCreateDatabaseAlways<AspnetIdentityWithOnionContext>
    {
        protected override void Seed(AspnetIdentityWithOnionContext context)
        {
            InitializeIdentityForEF(context);
            base.Seed(context);
        }

        //Create User=Admin@Admin.com with password=Admin@123456 in the Admin role        
        public void InitializeIdentityForEF(AspnetIdentityWithOnionContext db)
        {
            // This is only for testing purpose
            const string name = "admin@example.com";
            const string password = "Admin@123456";
            const string roleName = "Admin";
            var applicationRoleManager = IdentityFactory.CreateRoleManager(db);
            var applicationUserManager = IdentityFactory.CreateUserManager(db);
            //Create Role Admin if it does not exist
            var role = applicationRoleManager.FindByName(roleName);
            if (role == null)
            {
                role = new ApplicationIdentityRole(roleName);
                applicationRoleManager.Create(role);
            }

            var user = applicationUserManager.FindByName(name);
            if (user == null)
            {
                user = new ApplicationIdentityUser { UserName = name, Email = name };
                applicationUserManager.Create(user, password);
                applicationUserManager.SetLockoutEnabled(user.Id, false);
            }

            // Add user admin to Role Admin if not already added
            var rolesForUser = applicationUserManager.GetRoles(user.Id);
            if (!rolesForUser.Contains(role.Name))
            {
                applicationUserManager.AddToRole(user.Id, role.Name);
            }
            
            //### Developer Role and credentials
            const string name2 = "developer@example.com";
            const string password2 = "Developer@123456";
            const string roleName2 = "Developer";
            //Create Role Admin if it does not exist
            var role2 = applicationRoleManager.FindByName(roleName2);
            if (role2 == null)
            {
                role2 = new ApplicationIdentityRole(roleName2);
                applicationRoleManager.Create(role2);
            }

            var user2 = applicationUserManager.FindByName(name2);
            if (user2 == null)
            {
                user2 = new ApplicationIdentityUser { UserName = name2, Email = name2 };
                applicationUserManager.Create(user2, password2);
                applicationUserManager.SetLockoutEnabled(user2.Id, false);
            }

            // Add user admin to Role Admin if not already added
            var rolesForUser2 = applicationUserManager.GetRoles(user.Id);
            if (!rolesForUser2.Contains(role2.Name))
            {
                applicationUserManager.AddToRole(user2.Id, role2.Name);
            }

            var context = new AspnetIdentityWithOnionContext();
            var image = new Image {Path = "http://lorempixel.com/400/200/"};
            context.Set<Image>().Add(image);
            for (var i = 0; i < 100; i++)
            {
                context.Set<Product>().Add(new Product { Name = "My Product", Description = "My Product", Image = image });
            }
            context.SaveChanges();
        }
        class DebugLogger : ILogger
        {
            public void Log(string message)
            {
                
            }

            public void Log(Exception ex)
            {
                
            }
        }
    }
}