using System.Data;
using System.Data.Common;
using System.Data.Entity;
using System.Data.Entity.Core.Objects;
using System.Data.Entity.Infrastructure;
using System.Threading.Tasks;
using ASPNETIdentityWithOnion.Core.DomainModels;
using ASPNETIdentityWithOnion.Core.Logging;
using ASPNETIdentityWithOnion.Data.Identity.Models;
using Microsoft.AspNet.Identity.EntityFramework;
using ASPNETIdentityWithOnion.Core.Data;
using System.ComponentModel.DataAnnotations;
using ASPNETIdentityWithOnion.Data.Mappings;

namespace ASPNETIdentityWithOnion.Data
{
    public class AspnetIdentityWithOnionContext : IdentityDbContext<ApplicationIdentityUser, ApplicationIdentityRole, string, ApplicationIdentityUserLogin, ApplicationIdentityUserRole, ApplicationIdentityUserClaim>, IDbContext
    {
        private static readonly object Lock = new object();
        private static bool _databaseInitialized;

        public AspnetIdentityWithOnionContext()
            : base("name=AppContext") // use app.config transforms or web.config transforms to change this
        {
             if (_databaseInitialized)
             {
                 return;
             }
             lock (Lock)
             {
                 if (!_databaseInitialized)
                 {
                     // Set the database intializer which is run once during application start
                     // This seeds the database with admin user credentials and admin role
                     Database.SetInitializer(new ApplicationDbInitializer());
                     _databaseInitialized = true;
                 }
             }
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Configurations.Add(new ProductMapping());
            modelBuilder.Configurations.Add(new ImageMapping());
            EfConfig.ConfigureEf(modelBuilder);
        }



        public DbContext DbCtx
        {
            get { return this; }
        }
    }
}
