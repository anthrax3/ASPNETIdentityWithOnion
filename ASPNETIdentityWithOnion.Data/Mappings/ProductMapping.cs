using ASPNETIdentityWithOnion.Core.DomainModels;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity.ModelConfiguration;

namespace ASPNETIdentityWithOnion.Data.Mappings
{
    public class ProductMapping : EntityTypeConfiguration<Product>
    {
        public ProductMapping()
        {
            this.HasKey(t => t.Id);

            this.Property(t => t.Id)
                .HasDatabaseGeneratedOption(DatabaseGeneratedOption.None)
                .IsRequired();

            this.Property(t => t.Name)
                .HasMaxLength(256)
                .IsRequired();

            this.Property(t => t.Description)
                .HasMaxLength(500);

            this.Property(t => t.ImageID)
                .HasMaxLength(128)
                .IsRequired();

            // Foreign Key
            this.HasRequired(x => x.Image)
                .WithMany()
                .HasForeignKey(x => x.ImageID);
        }
    }
}
