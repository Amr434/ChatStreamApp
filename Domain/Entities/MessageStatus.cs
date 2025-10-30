using ChatApp.Infrastructure.Identity;
using System;

namespace ChatApp.Domain.Entities
{
    public class MessageStatus
    {
        // Composite Key (MessageId + UserId)
        public Guid MessageId { get; set; }
        public Message Message { get; set; } = null!;

        public Guid UserId { get; set; }
        public ApplicationUser User { get; set; } = null!;

        // Status info
        public bool IsDelivered { get; set; }   // Optional: for “Delivered ✓”
        public bool IsRead { get; set; }
        public DateTime? ReadAt { get; set; }

        // Optional
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
}
