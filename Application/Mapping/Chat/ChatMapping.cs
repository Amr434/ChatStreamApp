using Application.DTOs.Chat;
using Application.DTOs.User;
using AutoMapper;
using ChatApp.Domain.Entities;
using ChatApp.Infrastructure.Identity;
using Domain.Enums;

namespace Application.UserMapping
{
    public class ChatMapping : Profile
    {
        public ChatMapping()
        {
            // 🔹 Update chat room
            CreateMap<UpdateChatRoomDto, ChatRoom>()
                .ForMember(x => x.Name, y => y.MapFrom(t => t.Name))
                .ForMember(x => x.IsGroup, y => y.MapFrom(t => t.IsGroup))
                .ForMember(x => x.ProfileImageUrl, y => y.MapFrom(t => t.imageUrl))
                .ForMember(x => x.Id, y => y.MapFrom(t => t.chatRoomId))
                .ReverseMap();

            // 🔹 Chat room list
            CreateMap<ChatRoom, ChatRoomListDto>()
                   .ForMember(d => d.ChatRoomId, opt => opt.MapFrom(s => s.Id.ToString()))
                   .ForMember(d => d.ProfileImageUrl, opt => opt.MapFrom(s =>
                       s.IsGroup ? s.ProfileImageUrl :
                       s.UserChats.FirstOrDefault(uc => uc.UserId != Guid.Empty)
                       .User.ProfileImageUrl))
                   .ForMember(d => d.LastMessageContent, opt => opt.MapFrom(s =>
                       s.Messages.OrderByDescending(m => m.SentAt)
                       .Select(m => m.Content).FirstOrDefault()))
                   .ForMember(d => d.LastMessageSenderName, opt => opt.MapFrom(s =>
                       s.Messages.OrderByDescending(m => m.SentAt)
                           .Select(m => m.Sender.DisplayName ?? m.Sender.UserName).FirstOrDefault()))
                   .ForMember(d => d.LastMessageSentAt, opt => opt.MapFrom(s =>
                       s.Messages.OrderByDescending(m => m.SentAt)
                           .Select(m => (DateTime?)m.SentAt).FirstOrDefault()))
                   .ForMember(d => d.LastActivityAt, opt => opt.MapFrom(s =>
                       s.Messages.OrderByDescending(m => m.SentAt)
                           .Select(m => (DateTime?)m.SentAt).FirstOrDefault()))
                   .ForMember(d => d.UnreadCount, opt => opt.Ignore()); // you’ll likely compute it at runtime


            // 🔹 Create group chat (one-way)
            CreateMap<CreateGroupChatDto, ChatRoom>()
                .ForMember(x => x.Description, y => y.MapFrom(t => t.Description))
                .ForMember(x => x.Name, y => y.MapFrom(t => t.Name));

            // 🔹 UserChat ↔ UserChatDto
            CreateMap<UserChat, UserChatDto>()
                .ForMember(dest => dest.UserId, opt => opt.MapFrom(src => src.UserId.ToString()))
                .ForMember(dest => dest.FullName, opt => opt.MapFrom(src => src.User != null ? src.User.DisplayName : null))
                .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => src.User != null ? src.User.UserName : null))
                .ForMember(dest => dest.ProfileImageUrl, opt => opt.MapFrom(src => src.User != null ? src.User.ProfileImageUrl : null))
                .ForMember(dest => dest.IsOnline, opt => opt.MapFrom(src => src.User != null && src.User.Status == UserStatus.Online))
                .ForMember(dest => dest.IsMuted, opt => opt.MapFrom(src =>  src.IsMuted))
                .ForMember(dest => dest.IsAdmin, opt => opt.MapFrom(src =>  src.IsAdmin))
                .ForMember(dest => dest.LastSeen, opt => opt.MapFrom(src => src.User != null ? src.User.LastSeen.DateTime : DateTime.Now))
                .ReverseMap();

            // 🔹 ChatRoom ↔ ChatRoomDto
            CreateMap<ChatRoom, ChatRoomDto>()
                .ForMember(dest => dest.Name, opt => opt.MapFrom(src => src.Name))
                .ForMember(dest => dest.IsGroup, opt => opt.MapFrom(src => src.IsGroup))
                .ForMember(dest => dest.Description, opt => opt.MapFrom(src => src.Description))
                .ForMember(dest => dest.Members, opt => opt.MapFrom(src => src.UserChats))
                .ReverseMap();
        }
    }
}
