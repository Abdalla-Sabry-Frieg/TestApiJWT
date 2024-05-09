using System.IdentityModel.Tokens.Jwt;
using TestApiJWT.Models;

namespace TestApiJWT.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync (RegisterModel model);
        Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);

        // Add spasific Role to user 
        Task<String> AddRoleAsync(AddRoleModel model);
        Task<AuthModel> RefreshTokenAsync(string Token);
        Task<bool> RevokeTokenAsync(string Token);
    }
}
