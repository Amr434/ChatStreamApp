using ChatApp.Domain.Entities;
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

            builder.HasIndex(x => x.UserId);

            builder.HasOne(x => x.User)
                .WithMany(u => u.Connections)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }

    }
}
