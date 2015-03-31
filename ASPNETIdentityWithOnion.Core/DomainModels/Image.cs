using System;
using System.Collections.Generic;

namespace ASPNETIdentityWithOnion.Core.DomainModels
{
    public sealed class Image : BaseEntity
    {
        public Image()
        {
            this.Id = Guid.NewGuid().ToString();
            Products = new HashSet<Product>();
        }

        public string Path { get; set; }

        public ICollection<Product> Products { get; set; }
    }
}