using Application.Common.Model;
using Application.DTOs.Chat;
using Application.Interfaces;
using AutoMapper;
using AutoMapper.Execution;
using AutoMapper.QueryableExtensions;
using ChatApp.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Application.Services.Chat
{
    public class ChatRoomService : IChatRoomService
    {
        private readonly IUnitOfWork _unitOfwork;
        private readonly IMapper  _mapper;
        public ChatRoomService(IUnitOfWork unitOfwork,IMapper mapper)
        {
            _unitOfwork = unitOfwork;
            _mapper = mapper;
        }

        public async Task<Result<string>> AddUserToGroupChatAsync(AddUserToGroupChatDto dto)
        {
            if (string.IsNullOrEmpty(dto.chatRoomId) || string.IsNullOrEmpty(dto.userId))
                return Result<string>.Failure("ChatRoomId and UserId cannot be null or empty.");

            try
            {               
                var chatRoom = await _unitOfwork.ChatRoomRepository
                    .GetById(dto.chatRoomId, includeProperties: "UserChats");

                if (chatRoom == null)
                    return Result<string>.Failure("Chat room not found.");

                var userExists = await _unitOfwork.Users.ExistsAsync(u => u.Id.ToString() == dto.userId);
                if (!userExists)
                    return Result<string>.Failure("User not found.");

                var isMember = chatRoom.UserChats?.Any(uc => uc.UserId.ToString() == dto.userId) ?? false;
                if (isMember)
                    return Result<string>.Failure("User is already a member of this chat.");

                var userChat = new UserChat
                {
                    ChatRoomId = chatRoom.Id,
                    UserId = Guid.Parse(dto.userId),
                    Role = ChatRole.Admin,
                    JoinedAt = DateTime.UtcNow
                };

                chatRoom.UserChats.Add(userChat);
                await _unitOfwork.SaveChangesAsync();

                return Result<string>.SuccessResult("User successfully added to the group.");
            }
            catch (Exception ex)
            {
                return Result<string>.Failure($"An error occurred: {ex.Message}");
            }
        }

        public async Task<Result<ChatRoomDto>> CreateGroupChatAsync(CreateGroupChatDto dto)
        {
            if (dto is null)
                return Result<ChatRoomDto>.Failure("Invalid data.");

            if (string.IsNullOrWhiteSpace(dto.Name))
                return Result<ChatRoomDto>.Failure("Group name is required.");

            if (string.IsNullOrWhiteSpace(dto.CreatorId))
                return Result<ChatRoomDto>.Failure("CreatorId is required.");

            if (!Guid.TryParse(dto.CreatorId, out var creatorId))
                return Result<ChatRoomDto>.Failure("Invalid CreatorId format.");

            try
            {
                if (await _unitOfwork.ChatRoomRepository.ExistsAsync(c => c.Name == dto.Name && c.IsGroup))
                    return Result<ChatRoomDto>.Failure("A group chat with the same name already exists.");

                var memberGuids = dto.MemberIds.Distinct().Select(Guid.Parse).ToList();
                if (!memberGuids.Contains(creatorId))
                    memberGuids.Add(creatorId);

                var users = await _unitOfwork.Users.GetAllAsync(u => memberGuids.Contains(u.Id));
                if (!users.Any(u => u.Id == creatorId))
                    return Result<ChatRoomDto>.Failure("Creator user not found.");

                var chatRoom = _mapper.Map<ChatRoom>(dto);
                chatRoom.Id = Guid.NewGuid();
                chatRoom.IsGroup = true;
                chatRoom.CreatedAt = DateTime.UtcNow;
                chatRoom.CreatedById = creatorId;
                chatRoom.UserChats = memberGuids.Select(id => new UserChat
                {
                    ChatRoomId = chatRoom.Id,
                    UserId = id,
                    Role = id == creatorId ? ChatRole.Admin : ChatRole.Member,
                    JoinedAt = DateTime.UtcNow,
                    IsAdmin = id == creatorId
                }).ToList();

                await _unitOfwork.ChatRoomRepository.AddAsync(chatRoom);
                await _unitOfwork.SaveChangesAsync();

                var chatRoomResult = await _unitOfwork.ChatRoomRepository
                    .Query()
                    .Where(x => x.Id == chatRoom.Id)
                    .Include(x => x.UserChats).ThenInclude(o => o.User)
                    .AsNoTracking()
                    .FirstOrDefaultAsync();

                var resultDto = _mapper.Map<ChatRoomDto>(chatRoomResult);
                return Result<ChatRoomDto>.SuccessResult(resultDto);
            }
            catch (Exception ex)
            {
                return Result<ChatRoomDto>.Failure("An unexpected error occurred while creating the group chat.");
            }
        }


        public async Task<Result<ChatRoomDto>> CreatePrivateChatAsync(string user1Id, string user2Id)
        {
            if (string.IsNullOrEmpty(user1Id) || string.IsNullOrEmpty(user2Id))
                return Result<ChatRoomDto>.Failure("User IDs cannot be null or empty.");

            try
            {
                var user1Exists = await _unitOfwork.Users.ExistsAsync(u => u.Id.ToString() == user1Id);
                var user2Exists = await _unitOfwork.Users.ExistsAsync(u => u.Id.ToString() == user2Id);

                if (!user1Exists || !user2Exists)
                    return Result<ChatRoomDto>.Failure("One or both users not found.");

                var existingChat = await _unitOfwork.ChatRoomRepository
                    .GetPrivateChatBetweenUsersAsync(user1Id, user2Id);

                if (existingChat != null)
                    return Result<ChatRoomDto>.Failure("A private chat between these users already exists.");

                var chatRoom = new ChatRoom
                {
                    Id = Guid.NewGuid(),
                    IsGroup = false,
                    CreatedAt = DateTime.UtcNow,
                    Name = $"PrivateChat-{user1Id}-{user2Id}"
                };

                chatRoom.UserChats = new List<UserChat>
                {
                    new UserChat
                    {
                        ChatRoomId = chatRoom.Id,
                        UserId = Guid.Parse(user1Id),
                        Role = ChatRole.Member,
                        JoinedAt = DateTime.UtcNow
                    },
                    new UserChat
                    {
                        ChatRoomId = chatRoom.Id,
                        UserId = Guid.Parse(user2Id),
                        Role = ChatRole.Member,
                        JoinedAt = DateTime.UtcNow
                    }
                };

                await _unitOfwork.ChatRoomRepository.AddAsync(chatRoom);
                await _unitOfwork.SaveChangesAsync();

                var chatRoomDto = _mapper.Map<ChatRoomDto>(chatRoom);

                return Result<ChatRoomDto>.SuccessResult(chatRoomDto);
            }
            catch (Exception ex)
            {
                return Result<ChatRoomDto>.Failure($"An error occurred while creating private chat: {ex.Message}");
            }
        }


        public async Task<Result<string>> DeleteChatRoomAsync(string chatRoomId)
        {
            if (string.IsNullOrWhiteSpace(chatRoomId))
                return Result<string>.Failure("ChatRoomId cannot be null or empty.");

            try
            {
                var chatRoom = await _unitOfwork.ChatRoomRepository.GetById(chatRoomId);

                if (chatRoom == null)
                    return Result<string>.Failure($"No chat room found with ID: {chatRoomId}");

                await _unitOfwork.ChatRoomRepository.DeleteAsync(chatRoom);

                var changes = await _unitOfwork.SaveChangesAsync();

                if (changes <= 0)
                    return Result<string>.Failure("Failed to delete the chat room. No changes were saved.");

                return Result<string>.SuccessResult($"Chat room '{chatRoomId}' deleted successfully.");
            }
            catch (Exception ex)
            {
                return Result<string>.Failure($"An error occurred while deleting the chat room: {ex.Message}");
            }
        }


        public async Task<Result<string>> DemoteUserFromAdminAsync(string chatRoomId, string userId)
        {
            if (string.IsNullOrWhiteSpace(chatRoomId) || string.IsNullOrWhiteSpace(userId))
                return Result<string>.Failure("ChatRoomId and UserId cannot be null or empty.");

            try
            {
                var chatRoom = await _unitOfwork.ChatRoomRepository
                    .GetById(chatRoomId, includeProperties: "UserChats");

                if (chatRoom == null)
                    return Result<string>.Failure($"Chat room with ID '{chatRoomId}' not found.");

                var userChat = chatRoom.UserChats
                    .FirstOrDefault(x => x.UserId.ToString() == userId && x.Role == ChatRole.Admin);

                if (userChat == null)
                    return Result<string>.Failure("User is not an admin in this chat room.");

                // Demote to member
                userChat.Role = ChatRole.Member;

                // Update user-chat relation instead of the entire chat room if possible
                await _unitOfwork.ChatRoomRepository.UpdateAsync(chatRoom);

                var changes = await _unitOfwork.SaveChangesAsync();
                if (changes <= 0)
                    return Result<string>.Failure("No changes were saved. Demotion failed.");

                return Result<string>.SuccessResult($"User '{userId}' was demoted to member successfully.");
            }
            catch (Exception ex)
            {
                // In production, log the exception before returning
                return Result<string>.Failure($"An error occurred while demoting user from admin: {ex.Message}");
            }
        }

        public async Task<Result<IEnumerable<ChatRoomListDto>>> GetAllChatRoomsForUserAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result<IEnumerable<ChatRoomListDto>>.Failure("User ID cannot be null or empty.");

            try
            {
                var userExists = await _unitOfwork.Users.ExistsAsync(u => u.Id.ToString() == userId);
                if (!userExists)
                    return Result<IEnumerable<ChatRoomListDto>>.Failure($"User with ID '{userId}' not found.");

                var chatRooms = await _unitOfwork.ChatRoomRepository.GetAllChatRoomForUserAsync(userId);

                if (chatRooms == null || !chatRooms.Any())
                    return Result<IEnumerable<ChatRoomListDto>>.Failure("No chat rooms found for this user.");

       
                var chatRoomDtos = chatRooms.Select(_mapper.Map<ChatRoomListDto>).ToList();

                return Result<IEnumerable<ChatRoomListDto>>
                    .SuccessResult(chatRoomDtos);
            }
            catch (Exception ex)
            {
                return Result<IEnumerable<ChatRoomListDto>>
                    .Failure($"An error occurred while retrieving chat rooms: {ex.Message}");
            }
        }

        public async Task<Result<ChatRoomDto>> GetChatRoomByIdAsync(string chatRoomId)
        {
            if (string.IsNullOrWhiteSpace(chatRoomId))
                return Result<ChatRoomDto>.Failure("ChatRoomId cannot be null or empty.");

            if (!Guid.TryParse(chatRoomId, out var roomGuid))
                return Result<ChatRoomDto>.Failure("Invalid ChatRoomId format.");

            try
            {
                var chatRoom = await _unitOfwork.ChatRoomRepository
                    .Query()
                    .AsNoTracking()
                    .Where(x => x.Id == roomGuid)
                    .ProjectTo<ChatRoomDto>(_mapper.ConfigurationProvider)
                    .FirstOrDefaultAsync();

                if (chatRoom is null)
                    return Result<ChatRoomDto>.Failure($"No chat room found with ID: {chatRoomId}");

                return Result<ChatRoomDto>.SuccessResult(chatRoom);
            }
            catch (Exception ex)
            {
                return Result<ChatRoomDto>.Failure("An unexpected error occurred while retrieving the chat room.");
            }
        }

        public async Task<Result<IEnumerable<UserChatDto>>> GetGroupChatMembersAsync(string chatRoomId)
        {
            if (string.IsNullOrEmpty(chatRoomId))
                return Result<IEnumerable<UserChatDto>>.Failure("chat room id is null");
            try
            {
                var chatroom = await _unitOfwork.Users.GetAsync(x => x.Id.ToString() == chatRoomId);

                if (chatroom is null)
                    return Result<IEnumerable<UserChatDto>>.Failure("chat room not found.");

                var members = chatroom.UserChats.ToList();
                if (members != null || !members.Any())
                    return Result<IEnumerable<UserChatDto>>.Failure("chat room dosn`t contains any members");

                var membersMapper = members.Select(x => _mapper.Map<UserChatDto>(x));

                return Result<IEnumerable<UserChatDto>>.SuccessResult(membersMapper);

            }
            catch(Exception ex)
            {
                return Result<IEnumerable<UserChatDto>>.Failure($"ann error occured EX:{ex.Message}");
            }
        }

        public async Task<Result<IEnumerable<ChatRoomListDto>>> GetRecentChatsAsync(string userId, int limit = 10)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return Result<IEnumerable<ChatRoomListDto>>.Failure("User ID cannot be null or empty.");

            try
            {
                var userExists = await _unitOfwork.Users.ExistsAsync(userId);
                if (!userExists)
                    return Result<IEnumerable<ChatRoomListDto>>.Failure($"User with ID '{userId}' does not exist.");

                var chatRooms = await _unitOfwork.ChatRoomRepository
                    .Query()
                    .Where(cr => cr.UserChats.Any(uc => uc.UserId.ToString() == userId))
                    .OrderByDescending(cr => cr.LastMessage) 
                    .Take(limit)
                    .ProjectTo<ChatRoomListDto>(_mapper.ConfigurationProvider)
                    .ToListAsync();

                return Result<IEnumerable<ChatRoomListDto>>.SuccessResult(chatRooms);
            }
            catch (Exception ex)
            {
                // Optional: log exception here (via ILogger)
                return Result<IEnumerable<ChatRoomListDto>>.Failure($"An error occurred while fetching recent chats: {ex.Message}");
            }
        }

        public async Task<Result> PromoteUserToAdminAsync(string chatRoomId, string userId)
        {
            if (string.IsNullOrWhiteSpace(chatRoomId) || string.IsNullOrWhiteSpace(userId))
                return Result.Failure("ChatRoomId and UserId cannot be null or empty.");

            try
            {
                var chatRoom = await _unitOfwork.ChatRoomRepository
                    .GetById(chatRoomId, includeProperties: "UserChats");

                if (chatRoom == null)
                    return Result.Failure($"Chat room with ID '{chatRoomId}' was not found.");

                var userChat = chatRoom.UserChats.FirstOrDefault(uc => uc.UserId.ToString() == userId);
                if (userChat == null)
                    return Result.Failure($"User with ID '{userId}' is not a member of this chat room.");

                if (userChat.Role == ChatRole.Admin)
                    return Result.Failure("User is already an admin in this chat room.");

                userChat.Role = ChatRole.Admin;

                await _unitOfwork.ChatRoomRepository.UpdateAsync(chatRoom);
                var changes = await _unitOfwork.SaveChangesAsync();

                if (changes == 0)
                    return Result.Failure("No changes were saved to the database.");

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                return Result.Failure($"An error occurred while promoting user to admin: {ex.Message}");
            }
        }


        public async Task<Result> RemoveUserFromGroupChatAsync(string chatRoomId, string userId)
        {
            if (string.IsNullOrWhiteSpace(chatRoomId) || string.IsNullOrWhiteSpace(userId))
                return Result.Failure("ChatRoomId and UserId cannot be null or empty.");
            try
            {
                var ChatRoom = await _unitOfwork.ChatRoomRepository.GetById(chatRoomId,includeProperties:"UserChats");

                if (ChatRoom is null)
                    return Result.Failure("Chat Room not found");

                var user = ChatRoom.UserChats.FirstOrDefault(x=> x.UserId.ToString() == userId);

                if (user is null)
                    return Result.Failure("user is not found");

                ChatRoom.UserChats.Remove(user);

               await _unitOfwork.ChatRoomRepository.UpdateAsync(ChatRoom);

               var changes = await _unitOfwork.SaveChangesAsync();

                if(changes == 0) 
                    return Result.Failure("No changes were saved to the database.");

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                return Result.Failure($"An Error Occured While Remove User From Group Chat EX:{ex.Message}");
            }
        }

        public async Task<Result<IEnumerable<ChatRoomListDto>>> SearchChatRoomsAsync(string keyword, string userId)
        {
            if (string.IsNullOrEmpty(keyword) || string.IsNullOrEmpty(userId))
                return Result<IEnumerable<ChatRoomListDto>>.Failure("keyword and userid is null or empty");
            try
            {
                var parsedUserId = Guid.Parse(userId);

                var chatRooms = await _unitOfwork.ChatRoomRepository
                    .Query()
                    .Include(x => x.UserChats)
                        .ThenInclude(uc => uc.User)
                    .Where(x => x.UserChats.Any(y => y.UserId == parsedUserId)
                        && (string.IsNullOrEmpty(keyword) || EF.Functions.Like(x.Name, $"%{keyword}%")))
                    .Select(x => new ChatRoomListDto
                    {
                        ChatRoomId = x.Id.ToString(),
                        Name = x.Name,
                        Description = x.Description,
                        IsGroup = x.IsGroup,
                        ProfileImageUrl = x.ProfileImageUrl,
                        LastActivityAt = x.Messages
                            .OrderByDescending(m => m.SentAt)
                            .Select(m => (DateTime?)m.SentAt)
                            .FirstOrDefault(),

                        LastMessageContent = x.Messages
                            .OrderByDescending(m => m.SentAt)
                            .Select(m => m.Content)
                            .FirstOrDefault(),

                        LastMessageSenderName = x.Messages
                            .OrderByDescending(m => m.SentAt)
                            .Select(m => m.Sender.DisplayName)
                            .FirstOrDefault(),

                        LastMessageSentAt = x.Messages
                            .OrderByDescending(m => m.SentAt)
                            .Select(m => (DateTime?)m.SentAt)
                            .FirstOrDefault(),

                        UnreadCount = x.Messages
                            .Count(m => !m.MessageStatuses!
                                .Any(s => s.UserId == parsedUserId && s.IsRead)),

                        // For private chat — get the "other" user info
                        OtherUserId = !x.IsGroup
                            ? x.UserChats
                                .Where(uc => uc.UserId != parsedUserId)
                                .Select(uc => uc.User.Id.ToString())
                                .FirstOrDefault()
                            : null,

                        OtherUserName = !x.IsGroup
                            ? x.UserChats
                                .Where(uc => uc.UserId != parsedUserId)
                                .Select(uc => uc.User.DisplayName)
                                .FirstOrDefault()
                            : null,

                        OtherUserImageUrl = !x.IsGroup
                            ? x.UserChats
                                .Where(uc => uc.UserId != parsedUserId)
                                .Select(uc => uc.User.ProfileImageUrl)
                                .FirstOrDefault()
                            : null,

                        IsOnline = !x.IsGroup
                            ? x.UserChats
                                .Where(uc => uc.UserId != parsedUserId)
                                .Select(uc => uc.User.Status == Domain.Enums.UserStatus.Online)
                                .FirstOrDefault()
                            : false
                    })
                    .ToListAsync();




                if (chatRooms is null || !chatRooms.Any())
                    return Result<IEnumerable<ChatRoomListDto>>.Failure("Chat Room is null or Empty");

                return Result<IEnumerable<ChatRoomListDto>>.SuccessResult(chatRooms);
            }
            catch(Exception ex)
            {
                return Result<IEnumerable<ChatRoomListDto>>.Failure($"an error occured Ex:{ex.Message}");

            }
        }

        public async Task<Result> SetLastMessageAsync(string chatRoomId, string messageId)
        {
            if(string.IsNullOrEmpty(chatRoomId)||string.IsNullOrEmpty(messageId))
                return Result.Failure("ChatRoomId and UserId cannot be null or empty.");

            try
            {
                var ChatRoom = await _unitOfwork.ChatRoomRepository.GetById(chatRoomId);

                if (ChatRoom == null)
                    return Result.Failure("Chat Room is not found");

                var message = await _unitOfwork.MessageRepository
                    .GetAsync(x => x.Id.ToString() == messageId);

                if (message == null)
                    return Result.Failure("Message is null or empty");

                ChatRoom.LastMessage = message;
                ChatRoom.UpdatedAt = DateTime.Now;

                await _unitOfwork.ChatRoomRepository.UpdateAsync(ChatRoom);

               int changes = await _unitOfwork.SaveChangesAsync();

               if(changes == 0)
                   return Result.Failure("No changes were saved to the database.");

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                return Result.Failure($"ann error occured while set last message Ex:{ex.Message}");
            }

        }

        public async Task<Result> UpdateChatRoomAsync(UpdateChatRoomDto dto)
        {
            if (dto is null)
                return Result.Failure("Chat room data is required.");

            try
            {
                var chatRoom = await _unitOfwork.ChatRoomRepository
                    .GetAsync(x => x.Id.ToString() == dto.chatRoomId);

                if (chatRoom is null)
                    return Result.Failure("Chat room not found.");

                _mapper.Map(dto, chatRoom);

                chatRoom.UpdatedAt = DateTime.UtcNow; 

                await _unitOfwork.ChatRoomRepository.UpdateAsync(chatRoom);
                await _unitOfwork.SaveChangesAsync();

                return Result.SuccessResult();
            }
            catch (Exception ex)
            {
                return Result.Failure($"An error occurred while updating chat room: {ex.Message}");
            }
        }
    }
}
