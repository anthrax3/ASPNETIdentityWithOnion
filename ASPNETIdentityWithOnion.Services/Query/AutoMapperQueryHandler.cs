using ASPNETIdentityWithOnion.Core.Data;
using ASPNETIdentityWithOnion.Core.DomainModels;
using ASPNETIdentityWithOnion.Core.Extensions;
using ASPNETIdentityWithOnion.Core.Query;
using MediatR;
using Mehdime.Entity;
using System;
using System.Linq;
using System.Data.Entity;
using System.Collections.Generic;
using AutoMapper.QueryableExtensions;

namespace ASPNETIdentityWithOnion.Services.Query
{
    public class AutoMapperQueryHandler<TSrcEntity, TDestModel> : IRequestHandler<AutoMapperQuery<TSrcEntity, TDestModel>, IEnumerable<TDestModel>>
        where TSrcEntity : class
    {
        private readonly IDbContextScopeFactory _dbContextScopeFactory;

        public AutoMapperQueryHandler(IDbContextScopeFactory dbContextScopeFactory)
        {
            if (dbContextScopeFactory == null)
                throw new ArgumentNullException("dbContextScopeFactory");

            _dbContextScopeFactory = dbContextScopeFactory;
        }

        public IEnumerable<TDestModel> Handle(AutoMapperQuery<TSrcEntity, TDestModel> query)
        {
            using (var dbContextScope = _dbContextScopeFactory.CreateReadOnly())
            {
                // Gets our context from our context scope
                var dbCtx = dbContextScope.DbContexts.GetByInterface<IDbContext>();
                dbCtx.DbCtx.Configuration.ProxyCreationEnabled = false;
                var testSet = dbCtx.DbCtx.Set<TSrcEntity>().Project().To<TDestModel>().ToList();

                return testSet;
            }
        }
    }
}
