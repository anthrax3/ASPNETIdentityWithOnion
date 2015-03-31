using ASPNETIdentityWithOnion.Core.Data;
using Mehdime.Entity;
using System;

namespace ASPNETIdentityWithOnion.Core.Extensions
{
    public static class DbContextScopeExtensions
    {
        // These are set from the composition root
        public static Func<IAmbientDbContextLocator, Type, IDbContext> GetDbContextFromLocator;

        public static Func<IDbContextCollection, Type, IDbContext> GetDbContextFromCollection;

        public static T GetByInterface<T>(this IAmbientDbContextLocator locator) where T : class, IDbContext
        {
            return GetDbContextFromLocator(locator, typeof(T)) as T;
        }

        public static T GetByInterface<T>(this IDbContextCollection collection) where T : class, IDbContext
        {
            return GetDbContextFromCollection(collection, typeof(T)) as T;
        }
    }
}
