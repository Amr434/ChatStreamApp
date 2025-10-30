using ChatApp.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Configuration
{
    public class MessageReactionConfiguration : IEntityTypeConfiguration<MessageReaction>
    {
        public void Configure(EntityTypeBuilder<MessageReaction> builder)
        {
            builder.ToTable("MessageReactions");

            builder.HasKey(r => r.Id);

            builder.Property(r => r.ReactionType)
                   .HasConversion<int>() // store enum as int
                   .IsRequired();

            builder.Property(r => r.ReactedAt)
                   .HasDefaultValueSql("GETUTCDATE()");

            builder.HasOne(r => r.Message)
                   .WithMany(m => m.Reactions)
                   .HasForeignKey(r => r.MessageId)
                   .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(r => r.User)
                   .WithMany() 
                   .HasForeignKey(r => r.UserId)
                   .OnDelete(DeleteBehavior.Restrict);

            builder.HasIndex(r => new { r.MessageId, r.UserId })
                   .IsUnique();
        }
    }
}
