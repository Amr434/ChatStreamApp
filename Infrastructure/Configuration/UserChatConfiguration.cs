using ChatApp.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Configuration
{
    public class UserChatConfiguration : IEntityTypeConfiguration<UserChat>
    {
        public void Configure(EntityTypeBuilder<UserChat> builder)
        {
            builder.ToTable("UserChats");

            builder.HasKey(x => new { x.UserId, x.ChatRoomId });

            builder.Property(x => x.Role)
                .HasConversion<int>()
                   .HasDefaultValue(ChatRole.Member);

            builder.Property(x => x.JoinedAt)
                   .HasDefaultValueSql("GETUTCDATE()")
                   .IsRequired();

            builder.HasOne(x => x.User)
                   .WithMany(u => u.UserChats)
                   .HasForeignKey(x => x.UserId)
                   .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(x => x.ChatRoom)
                   .WithMany(c => c.UserChats)
                   .HasForeignKey(x => x.ChatRoomId)
                   .OnDelete(DeleteBehavior.Cascade);
        }
    }
}

