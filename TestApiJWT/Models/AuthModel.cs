using System.Text.Json.Serialization;

namespace TestApiJWT.Models
{
    public class AuthModel
    {
        // by this class will controll data that send to JWT to clint server
        public string Message { get; set; }
        public bool IsAuthenticated { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public List<string> Roles { get; set; }
        public string Token { get; set; }
         public DateTime ExpiresOn { get; set; } // the ExpiresOn to the token

        [JsonIgnore] // To set this prop  no't return at response
        public string RefreshToken { get; set; }
        // Will return the RefreshTokenExepiration to the refreshToken 
        public DateTime RefreshTokenExepiration { get; set; }
    }

}
