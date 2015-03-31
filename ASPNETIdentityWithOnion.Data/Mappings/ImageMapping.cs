using ASPNETIdentityWithOnion.Core.DomainModels;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity.ModelConfiguration;

namespace ASPNETIdentityWithOnion.Data.Mappings
{
    public class ImageMapping : EntityTypeConfiguration<Image>
    {
        public ImageMapping()
        {
            this.HasKey(t => t.Id);

            this.Property(t => t.Id)
                .HasDatabaseGeneratedOption(DatabaseGeneratedOption.None)
                .IsRequired();

            // Navigation Property
            this.HasMany(x => x.Products)
                .WithRequired(x=>x.Image)
                .WillCascadeOnDelete(false);
        }
    }
}
