using ChatApp.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Configuration
{
    class MessageConfiguration : IEntityTypeConfiguration<Message>
    {
        public void Configure(EntityTypeBuilder<Message> builder)
        {
            builder.ToTable("Messages");
            builder.HasKey(m => m.Id);

            builder.Property(m => m.Content)
                   .IsRequired()
                   .HasMaxLength(1000);

            builder.Property(m => m.SentAt)
                   .HasDefaultValueSql("GETUTCDATE()");


            builder.HasOne(m => m.ChatRoom)
                   .WithMany(c => c.Messages) 
                   .HasForeignKey(m => m.ChatRoomId)
                   .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(m => m.Sender)
                   .WithMany(u => u.Messages) 
                   .HasForeignKey(m => m.SenderId)
                   .OnDelete(DeleteBehavior.Restrict);

            builder.HasMany(m => m.Attachments)
                   .WithOne(a => a.Message) 
                   .HasForeignKey(a => a.MessageId)
                   .OnDelete(DeleteBehavior.Cascade);

            builder.HasMany(m => m.Reactions)
                   .WithOne(r => r.Message)
                   .HasForeignKey(r => r.MessageId)
                   .OnDelete(DeleteBehavior.Cascade);

            builder.HasMany(x=>x.MessageStatuses)
                   .WithOne(ms => ms.Message)
                   .HasForeignKey(ms => ms.MessageId)
                   .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
