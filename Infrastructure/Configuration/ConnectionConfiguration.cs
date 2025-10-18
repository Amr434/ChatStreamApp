using ChatApp.Domain.Entities;
using ChatterSphere.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.Configurations
{
    public class ConnectionConfiguration : IEntityTypeConfiguration<Connection>
    {
        public void Configure(EntityTypeBuilder<Connection> builder)
        {
            builder.ToTable("Connections");
            builder.HasKey(x => x.ConnectionId);

            builder.Property(x => x.ConnectionId)
                   .ValueGeneratedNever(); 

            builder.Property(x => x.ConnectedAt)
                   .HasDefaultValueSql("GETUTCDATE()");

            builder.HasOne(x => x.User)
                .WithMany(c => c.Connections)
               .HasForeignKey(x => x.UserId);
        }
    }
}
