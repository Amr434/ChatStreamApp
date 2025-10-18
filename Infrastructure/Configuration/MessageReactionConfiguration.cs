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
                   .IsRequired()
                   .HasMaxLength(50)
                   .HasDefaultValue("Like"); 

            builder.HasOne(r => r.Message)
                   .WithMany(m => m.Reactions) 

                   .HasForeignKey(r => r.MessageId)
                   .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(r => r.User)
                   .WithMany(u => u.MessageReactions)  

                   .HasForeignKey(r => r.UserId)
                   .OnDelete(DeleteBehavior.Restrict);
        }
    }
}
