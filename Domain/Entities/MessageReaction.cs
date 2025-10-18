using ChatApp.Domain.Entities;
using ChatApp.Infrastructure.Identity;
using System;

namespace ChatApp.Domain.Entities
{
    public class MessageReaction
    {
        public Guid Id { get; set; }
        public Guid MessageId { get; set; }
        public Message Message { get; set; } = null!;

        public Guid UserId { get; set; }
        public ApplicationUser User { get; set; } = null!;

        public string ReactionType { get; set; } = null!;
        public DateTime ReactedAt { get; set; } = DateTime.UtcNow;
    }
}
