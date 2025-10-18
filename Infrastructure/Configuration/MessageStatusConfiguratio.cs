using ChatApp.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Configuration
{
    public class MessageStatusConfiguration : IEntityTypeConfiguration<MessageStatus>
    {
        public void Configure(EntityTypeBuilder<MessageStatus> builder)
        {
            builder.ToTable("MessageStatuses");

            // Composite key
            builder.HasKey(ms => new { ms.MessageId, ms.UserId });

            builder.Property(ms => ms.IsRead)
                   .IsRequired()
                   .HasDefaultValue(false);

            builder.Property(ms => ms.ReadAt);

            builder.HasOne(ms => ms.Message)
                   .WithMany(m => m.MessageStatuses) 
                   .HasForeignKey(ms => ms.MessageId)
                   .OnDelete(DeleteBehavior.Cascade);

           
            builder.HasOne(ms => ms.User)
                   .WithMany(u => u.MessageStatuses) 

                   .HasForeignKey(ms => ms.UserId)
                   .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
