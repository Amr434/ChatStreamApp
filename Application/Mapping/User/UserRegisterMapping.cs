using Application.DTOs.User;
using AutoMapper;
using ChatApp.Infrastructure.Identity;
namespace Application.UserMapping
{

    public class UserRegisterMapping : Profile
    {
        public UserRegisterMapping()
        {
            CreateMap<RegisterDto, ApplicationUser>()
                .ForMember(x => x.UserName, y => y.MapFrom(t => t.UserName))
                .ForMember(x => x.Email, y => y.MapFrom(t => t.Email))
                .ReverseMap();

                
        }
    }
}