using ASPNETIdentityWithOnion.Core.Query;
using ASPNETIdentityWithOnion.Services.Query;
using Autofac;
using Autofac.Features.Variance;
using MediatR;
using System;
using System.Collections.Generic;

namespace ASPNETIdentityWithOnion.Bootstrapper
{
    public class MediatorModule : Module
    {
        //private readonly System.Reflection.Assembly[] _assembliesToScan;
        
        //public MediatorModule(params System.Reflection.Assembly[] assembliesToScan)
        //{
        //    _assembliesToScan = assembliesToScan;
        //}
 
        protected override void Load(ContainerBuilder builder)
        {
            builder.RegisterSource(new ContravariantRegistrationSource());
            builder.RegisterAssemblyTypes(typeof(IMediator).Assembly).AsImplementedInterfaces();
            //builder.RegisterAssemblyTypes(typeof(ProductQueryHandler).Assembly).AsImplementedInterfaces();
            var asy = System.Reflection.Assembly.Load("ASPNETIdentityWithOnion.Services");
            builder.RegisterAssemblyTypes(asy)
                .AsClosedTypesOf(typeof(IRequestHandler<,>))
                .AsImplementedInterfaces();


            builder.RegisterGeneric(typeof(AutoMapperQuery<,>)).AsSelf();
            builder.RegisterGeneric(typeof(AutoMapperQueryHandler<,>))
                .As(typeof(IRequestHandler<,>));

            builder.RegisterGeneric(typeof(GenericQuery<>)).AsSelf();
            builder.RegisterGeneric(typeof(GenericQueryHandler<>))
                .As(typeof(IRequestHandler<,>));
            //builder.RegisterGeneric(typeof(AutoMapQueryHandlerTest<,>))
            //    .As(typeof(IRequestHandler<,>));
            var assemblies = AppDomain.CurrentDomain.GetAssemblies();
            builder.Register<SingleInstanceFactory>(ctx =>
            {
                var c = ctx.Resolve<IComponentContext>();
                return t => c.Resolve(t);
            });
            builder.Register<MultiInstanceFactory>(ctx =>
            {
                var c = ctx.Resolve<IComponentContext>();
                return t => (IEnumerable<object>)c.Resolve(typeof(IEnumerable<>).MakeGenericType(t));
            });
        }
    }
}
