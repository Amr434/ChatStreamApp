using ChatApp.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.Configurations
{
    public class ChatRoomConfiguration : IEntityTypeConfiguration<ChatRoom>
    {
        public void Configure(EntityTypeBuilder<ChatRoom> builder)
        {
            builder.ToTable("ChatRooms");

            builder.HasKey(x => x.Id);

            builder.Property(x => x.Name)
                .IsRequired()
                .HasMaxLength(100);

            builder.Property(x => x.CreatedAt)
                .HasDefaultValueSql("GETUTCDATE()");

            builder.HasMany(x => x.Messages)
                .WithOne(x => x.ChatRoom)
                .HasForeignKey(x => x.ChatRoomId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasMany(x=>x.UserChats)
                .WithOne(x => x.ChatRoom)
                .HasForeignKey(x => x.ChatRoomId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
