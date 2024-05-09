using Humanizer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Xml;
using TestApiJWT.Helpers;
using TestApiJWT.Models;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

namespace TestApiJWT.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _JWT;

        public AuthService(UserManager<ApplicationUser>  userManager , IOptions<JWT> JWT , RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _JWT = JWT.Value;
        }
        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
           if(await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel {Message = $"Email is already registered!" };

            if (await _userManager.FindByNameAsync(model.Username) is not null)
                return new AuthModel { Message = $"UserName is already registered!" };

            // new user will created
            var newUser = new ApplicationUser()
            {
                Email = model.Email,
                UserName = model.Username,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };

            var result = await _userManager.CreateAsync(newUser, model.Password);

            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                {
                    errors += $"{error.Description}";
                }

                return new AuthModel() { Message = errors};
            }

            // Add new users to default role "User"

            var addDefaultRole = await _userManager.AddToRoleAsync(newUser, "User");

            // Send token 

            var jwtSecurityToken = await CreateJwtToken(newUser);

            return new AuthModel()
            {
                Email=model.Email,
                Username=model.Username,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User"},
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken)
            };

        }

        public async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaim = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles) 
            {
                roleClaims.Add(new Claim("roles", role));
            }

            var Claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim("uid" , user.Id),
                
            }.Union(userClaim)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_JWT.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(

                issuer : _JWT.Issuer,
                audience : _JWT.Audience,
                signingCredentials : signingCredentials,
                claims:Claims,
                expires:DateTime.UtcNow.AddMinutes(_JWT.DurationInMinutes)
                );

            return jwtSecurityToken;

        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user,model.Password)) 
            {
                 authModel.Message =" Email or Password is incorrect!";
                return authModel;
            }

            var jwtSecurityToken = await CreateJwtToken(user); 
            var RoleList = await _userManager.GetRolesAsync(user);
            

            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.Roles = RoleList.ToList();
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.IsAuthenticated=true;

            if(user.RefreshTokens.Any(t=>t.IsActive)) // Any refresh token is active
            { 
                var activeRefreshToken = user.RefreshTokens.FirstOrDefault(x => x.IsActive);
                authModel.RefreshToken = activeRefreshToken.Token;
                authModel.RefreshTokenExepiration = activeRefreshToken.ExpiresOn;

            }
            else // if no active token will generate a new Refresh Token
            {
                var refreshToken = GenerateRefreshToken();
                authModel.RefreshToken = refreshToken.Token;
                authModel.RefreshTokenExepiration= refreshToken.ExpiresOn;
                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);

            }


            return authModel;


        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if(user==null || !await _roleManager.RoleExistsAsync(model.RoleName))
            {
                return "Invalid user ID or Role name";
            }

            var result = await _userManager.AddToRoleAsync(user, model.RoleName);

            return result.Succeeded ? string.Empty : "Sonething went wrong";
        }

        private RefreshToken GenerateRefreshToken()
        {
            var random = new byte[32];
            var generator = new RNGCryptoServiceProvider();
            generator.GetBytes(random);

            return new RefreshToken()
            {
                Token = Convert.ToBase64String(random),
                ExpiresOn= DateTime.UtcNow.AddDays(10), // will expire after 10 days
                CreatedOn = DateTime.UtcNow,
            };
        }

        public async Task<AuthModel> RefreshTokenAsync(string Token)
        {
            var authmodel = new AuthModel();

            // Logic 

            // check if any users have a any refresh token in database
            var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == Token));

            if(user==null)
            {
                authmodel.IsAuthenticated = false;
                authmodel.Message = "Invalid Token";
                return authmodel;
            }

            // chech if return token from selected user == the token in the parameter
            var refreshToken = user.RefreshTokens.Single(t=>t.Token ==Token);

            if(!refreshToken.IsActive)
            {
                authmodel.IsAuthenticated = false;
                authmodel.Message = "Inactive Token";
                return authmodel;
            }

            // Revove for old refresh token
            refreshToken.RevokedOn = DateTime.UtcNow;

            // Add new Refreah token & assinged to user in database
            var NewRefreshToken = GenerateRefreshToken();

            user.RefreshTokens.Add(NewRefreshToken);
            await _userManager.UpdateAsync(user);

            // Generate new JWT 
            var jwtToken = await CreateJwtToken(user);

            authmodel.IsAuthenticated = true;
            authmodel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            authmodel.Email = user.Email;
            authmodel.Username = user.UserName;
            var roles =await _userManager.GetRolesAsync(user);
            authmodel.Roles = roles.ToList();
            authmodel.RefreshToken = NewRefreshToken.Token;
            authmodel.RefreshTokenExepiration = NewRefreshToken.ExpiresOn;


            return authmodel;

        }

        public async Task<bool> RevokeTokenAsync(string Token)
        {
            var user = await _userManager.Users.SingleOrDefaultAsync(t => t.RefreshTokens.Any(x => x.Token == Token));

            if(user==null) 
            {
                return false;
            }

            var refreshToken =  user.RefreshTokens.Single(x=>x.Token == Token);

            if(!refreshToken.IsActive) 
            {
                return false;
            }

            refreshToken.RevokedOn = DateTime.UtcNow;

            await _userManager.UpdateAsync(user);

            return true;
            
        }
    }
}
