using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestApiJWT.Models;
using TestApiJWT.Services;

namespace TestApiJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        //  Register endPoint
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if(!ModelState.IsValid) 
            {
                return BadRequest(ModelState);
            }

            var result =await _authService.RegisterAsync(model);

            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            }

            // Generate new Refresh cookie with response 
            setRefreshToken(result.RefreshToken ,result.RefreshTokenExepiration);

            // Here return all data to clint side 
           return Ok(result);

            // Here return custom data about anonymous object

            //return Ok(new {token = result.Token , username = result.Username , email = result.Email});

        }

        // Generate Token endPoint

        [HttpPost("GetToken")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _authService.GetTokenAsync(model);

            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            }

            // Add Check for RefreshToken
            if(!string.IsNullOrEmpty(result.RefreshToken))
            {
                // Generate new Cookie  with Refreash token 
                setRefreshToken(result.RefreshToken , result.RefreshTokenExepiration);
            }

            return Ok(result);
        } 
        

        // Add Role to user EndPoint

        [HttpPost("AddSpacificRole")]
        public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _authService.AddRoleAsync(model);

            if (!string.IsNullOrEmpty(result))
            {
                return BadRequest(result);
            }

            return Ok(model);
        }



        // Generate Refresh token endpoint Cookies method
        [HttpGet("RefreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var RefreshToken = Request.Cookies["ResreshToken"];

            var result = await _authService.RefreshTokenAsync(RefreshToken);

            if(!result.IsAuthenticated)
            {
                return BadRequest(result);
            }

            // Add new refresh token that return from cookie
            setRefreshToken(result.RefreshToken , result.RefreshTokenExepiration );

            return Ok(result);


        }



        // Add End ponit to revoked to token
        // Any endpoint works with a request.cookies
        [HttpPost("RevokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeModel model)
        {
            var token = model.Token ?? Request.Cookies["ResreshToken"];
            if (string.IsNullOrEmpty(token))  // لو فاضي 
            {
                return BadRequest("Token is Required");   
            }

            var result = await _authService.RevokeTokenAsync(token);

            if(!result)
                return BadRequest("Token is Invalid");

            return Ok(result);

        }

        // privet method to add new cookie with any response to add new cookie
        private void setRefreshToken(string refreshToken , DateTime expires)
        {
            var cookiOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expires.ToLocalTime(),
                Secure = true,
                IsEssential =true,
                SameSite =SameSiteMode.None, 

            };
            // add new cooki  (cooki name ,refreshToken name , CookiOptions  )
            Response.Cookies.Append("ResreshToken", refreshToken, cookiOptions);
     
        }


    }
}
