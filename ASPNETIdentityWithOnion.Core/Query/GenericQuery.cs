using MediatR;
using System.Collections.Generic;

namespace ASPNETIdentityWithOnion.Core.Query
{
    public class GenericQuery<TEntity> : IRequest<IEnumerable<TEntity>>
    {
    }
}
