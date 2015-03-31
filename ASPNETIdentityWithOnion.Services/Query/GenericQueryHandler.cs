﻿using ASPNETIdentityWithOnion.Core.Query;
using MediatR;
using Mehdime.Entity;
using ASPNETIdentityWithOnion.Core.Extensions;
using ASPNETIdentityWithOnion.Core.Data;
using System.Collections.Generic;
using System;
using System.Linq;

namespace ASPNETIdentityWithOnion.Services.Query
{
    public class GenericQueryHandler<TEntity> : IRequestHandler<GenericQuery<TEntity>, IEnumerable<TEntity>>
        where TEntity : class
    {
        private readonly IDbContextScopeFactory _dbContextScopeFactory;

        public GenericQueryHandler(IDbContextScopeFactory dbContextScopeFactory)
        {
            if (dbContextScopeFactory == null)
                throw new ArgumentNullException("dbContextScopeFactory");

            _dbContextScopeFactory = dbContextScopeFactory;
        }

        public IEnumerable<TEntity> Handle(GenericQuery<TEntity> query)
        {
            using (var dbContextScope = _dbContextScopeFactory.CreateReadOnly())
            {
                var dbCtx = dbContextScope.DbContexts.GetByInterface<IDbContext>();
                dbCtx.DbCtx.Configuration.ProxyCreationEnabled = false;
                var testSet = dbCtx.DbCtx.Set<TEntity>().ToList();

                return testSet;
            }
        }
    }
}
