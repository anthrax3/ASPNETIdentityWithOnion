using ASPNETIdentityWithOnion.Core.Extensions;
using ASPNETIdentityWithOnion.Data;

namespace ASPNETIdentityWithOnion.Bootstrapper
{
    public static class DbContextScopeExtensionConfig
    {
        public static void Setup()
        {
            DbContextScopeExtensions.GetDbContextFromCollection = (collection, type) =>
            {
                return collection.Get<AspnetIdentityWithOnionContext>();
            };

            DbContextScopeExtensions.GetDbContextFromLocator = (locator, type) =>
            {
                return locator.Get<AspnetIdentityWithOnionContext>();
            };
        }
    }
}
