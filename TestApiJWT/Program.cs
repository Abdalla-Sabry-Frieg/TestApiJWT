using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Configuration;
using System.Text;
using TestApiJWT.Data;
using TestApiJWT.Helpers;
using TestApiJWT.Models;
using TestApiJWT.Services;

var builder = WebApplication.CreateBuilder(args);


// To mapping with this prop
builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));


// Add Connections Strings
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Add Identity users 
builder.Services.AddIdentity<ApplicationUser,IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.AddScoped<IAuthService, AuthService>();

// Add Authentications for JWT Bearear and default schema
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
        {
            o.RequireHttpsMetadata = false;
            o.SaveToken = false;
            o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidIssuer = builder.Configuration["JWT:Issuer"],
                ValidAudience= builder.Configuration["JWT:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"])),
                // معناه ان التوكن لحظه ما وقته يخلص الي انا محددهاله هي ال appsettins يوقف عمل التوكن دا خالص ولازم توكن جديد او Refresh Token
                ClockSkew=TimeSpan.Zero
            };
});
// Add services to CORS 
//builder.Services.AddCors(corsOptions =>
//{
//    corsOptions.AddPolicy("MyPolicy1", CorsPolicyBuilder =>
//    {
//        CorsPolicyBuilder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
//    });
//});

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen();

// Add services to the container.
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//app.UseCors("MyPolicy1");

app.UseStaticFiles();

// very important middleware 
app.UseHttpsRedirection();


app.UseAuthentication();
app.UseAuthorization();

//app.UseRouting();
app.UseHttpsRedirection();

app.MapControllers();

app.Run();
