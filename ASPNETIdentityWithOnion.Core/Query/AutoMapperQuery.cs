using MediatR;
using System.Collections.Generic;

namespace ASPNETIdentityWithOnion.Core.Query
{
    public class AutoMapperQuery<TSrcEntity, TDestModel> : IRequest<IEnumerable<TDestModel>>
    {
    }
}
