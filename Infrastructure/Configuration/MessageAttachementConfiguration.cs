using ChatApp.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Configuration
{
    public class MessageAttachmentConfiguration : IEntityTypeConfiguration<MessageAttachment>
    {
        public void Configure(EntityTypeBuilder<MessageAttachment> builder)
        {
            builder.ToTable("MessageAttachments");

            builder.HasKey(a => a.Id);

            builder.Property(a => a.FileUrl)
                   .IsRequired()
                   .HasMaxLength(500);

            builder.Property(a => a.FileType)
                   .IsRequired()
                   .HasMaxLength(50);

            builder.HasOne(a => a.Message)
                   .WithMany(m => m.Attachments)
                   .HasForeignKey(a => a.MessageId)
                   .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
