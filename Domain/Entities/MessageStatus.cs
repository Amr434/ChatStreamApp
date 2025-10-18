using ChatApp.Domain.Entities;
using ChatApp.Infrastructure.Identity;

public class MessageStatus
{
    public Guid MessageId { get; set; }
    public Message Message { get; set; } = null!;

    public Guid UserId { get; set; }
    public ApplicationUser User { get; set; } = null!;

    public bool IsRead { get; set; }
    public DateTime? ReadAt { get; set; }
}
