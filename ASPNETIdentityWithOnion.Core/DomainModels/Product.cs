using System;
namespace ASPNETIdentityWithOnion.Core.DomainModels
{
    public class Product : BaseEntity
    {
        public Product()
        {
            this.Id = Guid.NewGuid().ToString();
        }

        public string Name { get; set; }
        public string Description { get; set; }
        public string ImageID { get; set; }
        public virtual Image Image { get; set; }
    }
}