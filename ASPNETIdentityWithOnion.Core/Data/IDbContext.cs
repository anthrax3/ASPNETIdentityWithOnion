using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASPNETIdentityWithOnion.Core.Data
{
    public interface IDbContext
    {
        DbContext DbCtx { get; }
    }
}
