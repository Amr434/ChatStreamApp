using ChatApp.Infrastructure.Identity;
using System;

namespace ChatApp.Domain.Entities
{
    public class MessageReaction
    {
        public Guid Id { get; set; }

        // Foreign Key to Message
        public Guid MessageId { get; set; }
        public Message Message { get; set; } = null!;

        // Foreign Key to User
        public Guid UserId { get; set; }
        public ApplicationUser User { get; set; } = null!;

        // Reaction details
        public  ReactionType ReactionType{ get; set; }    // e.g., "like", "love", "laugh", "sad"
        public DateTime ReactedAt { get; set; } = DateTime.UtcNow;
    }
    public enum ReactionType
    {
        Like,
        Love,
        Laugh,
        Sad,
        Angry,
        Wow
    }

}
