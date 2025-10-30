
namespace Application.DTOs.Chat
{
    public class CreateGroupChatDto
    {
        public string CreatorId { get; set; } = null!;
        public string Name { get; set; } = null!;
        public string? Description { get; set; }
        public List<string> MemberIds { get; set; } = new();
    }
}
