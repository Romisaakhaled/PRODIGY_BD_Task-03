using JwtAuthenticationAndAuthorization;
using JwtAuthenticationAndAuthorization.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// ✅ استخدم مفتاح سري بطول 32 حرف على الأقل (256 بت)
var secretKey = "My_Secret_Key_That_Is_32_Chars_Long!";
var key = Encoding.UTF8.GetBytes(secretKey);

// ✅ إعدادات المصادقة باستخدام JWT
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "yourIssuer",
        ValidAudience = "yourAudience",
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

// ✅ إعدادات التصاريح حسب الأدوار
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireRole("admin"));
    options.AddPolicy("User", policy => policy.RequireRole("user"));
    options.AddPolicy("Owner", policy => policy.RequireRole("owner"));
});

builder.Services.AddSingleton<IUserRepository, InMemoryUserRepository>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "JwtAuthenticationAndAuthorization", Version = "v1" });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer' [space] and then your valid token in the text input below.\r\n\r\nExample: \"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"",
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});


var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", async (UserDto userDto, IUserRepository repo) =>
{
    var hashedPassword = BCrypt.Net.BCrypt.HashPassword(userDto.Password);
    var user = new User
    {
        Username = userDto.Username,
        PasswordHash = hashedPassword,
        Role = userDto.Role
    };
    repo.AddUser(user);
    return Results.Ok("User registered successfully");
});

app.MapPost("/login", (UserDto userDto, IUserRepository repo) =>
{
    var user = repo.GetUser(userDto.Username);
    if (user is null || !BCrypt.Net.BCrypt.Verify(userDto.Password, user.PasswordHash))
        return Results.Unauthorized();

    var tokenHandler = new JwtSecurityTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("sub", user.Username),
            new Claim("role", user.Role)
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        Issuer = "yourIssuer",
        Audience = "yourAudience",
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    return Results.Ok(new { token = tokenHandler.WriteToken(token) });
});

app.MapGet("/profile", [Authorize] (ClaimsPrincipal user) =>
{
    var username = user.Identity?.Name ?? user.FindFirst("sub")?.Value;
    return Results.Ok($"Welcome, {username}");
});

app.MapGet("/admin", [Authorize(Policy = "Admin")] () => "Admin access granted.");
app.MapGet("/owner", [Authorize(Policy = "Owner")] () => "Owner access granted.");
app.MapGet("/user", [Authorize(Policy = "User")] () => "User access granted.");

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.Run();
