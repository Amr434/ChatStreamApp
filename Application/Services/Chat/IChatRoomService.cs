using Application.Common.Model;
using Application.DTOs.Chat;
namespace Application.Services.Chat
{
    
        public interface IChatRoomService
        {
            Task<Result<ChatRoomDto>> CreatePrivateChatAsync(string user1Id, string user2Id);
            Task<Result<ChatRoomDto>> CreateGroupChatAsync(CreateGroupChatDto createGroupChatDto);
            Task<Result> UpdateChatRoomAsync(UpdateChatRoomDto dto);
            Task<Result<string>> DeleteChatRoomAsync(string chatRoomId);

            Task<Result<ChatRoomDto>> GetChatRoomByIdAsync(string chatRoomId);
            Task<Result<IEnumerable<ChatRoomListDto>>> GetAllChatRoomsForUserAsync(string userId);
            Task<Result<IEnumerable<UserChatDto>>> GetGroupChatMembersAsync(string chatRoomId);

        Task<Result<string>> AddUserToGroupChatAsync(AddUserToGroupChatDto dto);
            Task<Result> RemoveUserFromGroupChatAsync(string chatRoomId, string userId);
            Task<Result> PromoteUserToAdminAsync(string chatRoomId, string userId);
            public Task<Result<string>> DemoteUserFromAdminAsync(string chatRoomId, string userId);

            Task<Result> SetLastMessageAsync(string chatRoomId, string messageId);
            Task<Result<IEnumerable<ChatRoomListDto>>> SearchChatRoomsAsync(string keyword, string userId);
            Task<Result<IEnumerable<ChatRoomListDto>>> GetRecentChatsAsync(string userId, int limit = 10);
        }
}
