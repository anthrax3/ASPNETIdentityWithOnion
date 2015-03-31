using System.Web.Mvc;
using ASPNETIdentityWithOnion.Bootstrapper;
using ASPNETIdentityWithOnion.Core.Data;
using ASPNETIdentityWithOnion.Core.Logging;
using ASPNETIdentityWithOnion.Data;
using ASPNETIdentityWithOnion.Infrastructure.Logging;
using ASPNETIdentityWithOnion.Services;
using ASPNETIdentityWithOnion.Web;
using Autofac;
using Autofac.Integration.Mvc;
using Mehdime.Entity;
using System.Web.Compilation;
using System.Linq;

[assembly: WebActivatorEx.PreApplicationStartMethod(typeof(IocConfig), "RegisterDependencies")]

namespace ASPNETIdentityWithOnion.Bootstrapper
{
    public class IocConfig
    {
        public static void RegisterDependencies()
        {
            const string nameOrConnectionString = "name=AppContext";
            DbContextScopeExtensionConfig.Setup();

            var builder = new ContainerBuilder();
            builder.RegisterControllers(typeof(MvcApplication).Assembly);
            builder.RegisterModule<AutofacWebTypesModule>();
            builder.RegisterType<DbContextScopeFactory>().As<IDbContextScopeFactory>().SingleInstance();
            builder.Register(b => NLogLogger.Instance).SingleInstance();
            builder.RegisterModule(new IdentityModule());
            builder.RegisterModule(new MediatorModule());
            
            var container = builder.Build();
            DependencyResolver.SetResolver(new AutofacDependencyResolver(container));
        }
    }
}
