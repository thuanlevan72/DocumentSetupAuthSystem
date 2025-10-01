using DocumentManagementSystem.Data;
using DocumentManagementSystem.DTOs;
using DocumentManagementSystem.Models;
using DocumentManagementSystem.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace DocumentManagementSystem.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenService _tokenService;
    private readonly ApplicationDbContext _context;
    private readonly IConfiguration _configuration;
    
    public AuthController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService,
        ApplicationDbContext context,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _context = context;
        _configuration = configuration;
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            FullName = model.FullName,
            DateOfBirth = model.DateOfBirth,
            Department = model.Department
        };
        
        var result = await _userManager.CreateAsync(user, model.Password);
        
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors });
        }
        
        await _userManager.AddToRoleAsync(user, "Viewer");
        
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        
        return Ok(new
        {
            message = "User registered successfully. Please confirm your email.",
            userId = user.Id,
            emailConfirmationToken = token
        });
    }
    
    [HttpPost("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailDto model)
    {
        var user = await _userManager.FindByIdAsync(model.UserId);
        if (user == null)
        {
            return NotFound(new { message = "User not found" });
        }
        
        var result = await _userManager.ConfirmEmailAsync(user, model.Token);
        
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors });
        }
        
        return Ok(new { message = "Email confirmed successfully" });
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            return Unauthorized(new { message = "Invalid credentials" });
        }
        
        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            return Unauthorized(new { message = "Email not confirmed" });
        }
        
        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
        
        if (!result.Succeeded)
        {
            if (result.IsLockedOut)
            {
                return Unauthorized(new { message = "Account is locked out" });
            }
            return Unauthorized(new { message = "Invalid credentials" });
        }
        
        var roles = await _userManager.GetRolesAsync(user);
        var userClaims = await _userManager.GetClaimsAsync(user);
        
        var accessToken = _tokenService.GenerateAccessToken(user, roles, userClaims.ToList());
        var refreshToken = _tokenService.GenerateRefreshToken();
        
        var refreshTokenEntity = new RefreshToken
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };
        
        _context.RefreshTokens.Add(refreshTokenEntity);
        await _context.SaveChangesAsync();
        
        Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = refreshTokenEntity.ExpiresAt
        });
        
        return Ok(new AuthResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            Email = user.Email ?? string.Empty,
            FullName = user.FullName ?? string.Empty,
            Roles = roles.ToList(),
            ExpiresAt = DateTime.UtcNow.AddMinutes(15)
        });
    }
    
    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto model)
    {
        var refreshToken = model.RefreshToken ?? Request.Cookies["refreshToken"];
        
        if (string.IsNullOrEmpty(refreshToken))
        {
            return BadRequest(new { message = "Refresh token is required" });
        }
        
        var storedToken = await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken);
        
        if (storedToken == null || !storedToken.IsActive)
        {
            return Unauthorized(new { message = "Invalid refresh token" });
        }
        
        var principal = _tokenService.GetPrincipalFromExpiredToken(model.AccessToken);
        if (principal == null)
        {
            return Unauthorized(new { message = "Invalid access token" });
        }
        
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId != storedToken.UserId)
        {
            return Unauthorized(new { message = "Token mismatch" });
        }
        
        var user = storedToken.User;
        var roles = await _userManager.GetRolesAsync(user);
        var userClaims = await _userManager.GetClaimsAsync(user);
        
        var newAccessToken = _tokenService.GenerateAccessToken(user, roles, userClaims.ToList());
        var newRefreshToken = _tokenService.GenerateRefreshToken();
        
        storedToken.IsRevoked = true;
        storedToken.ReplacedByToken = newRefreshToken;
        
        var newRefreshTokenEntity = new RefreshToken
        {
            Token = newRefreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };
        
        _context.RefreshTokens.Add(newRefreshTokenEntity);
        await _context.SaveChangesAsync();
        
        Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = newRefreshTokenEntity.ExpiresAt
        });
        
        return Ok(new AuthResponseDto
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            Email = user.Email ?? string.Empty,
            FullName = user.FullName ?? string.Empty,
            Roles = roles.ToList(),
            ExpiresAt = DateTime.UtcNow.AddMinutes(15)
        });
    }
    
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (!string.IsNullOrEmpty(userId))
        {
            var tokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && !rt.IsRevoked)
                .ToListAsync();
            
            foreach (var token in tokens)
            {
                token.IsRevoked = true;
            }
            
            await _context.SaveChangesAsync();
        }
        
        Response.Cookies.Delete("refreshToken");
        await _signInManager.SignOutAsync();
        
        return Ok(new { message = "Logged out successfully" });
    }
    
    [Authorize]
    [HttpPost("enable-2fa")]
    public async Task<IActionResult> EnableTwoFactor()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var user = await _userManager.FindByIdAsync(userId ?? string.Empty);
        
        if (user == null)
        {
            return NotFound(new { message = "User not found" });
        }
        
        await _userManager.SetTwoFactorEnabledAsync(user, true);
        var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
        
        if (string.IsNullOrEmpty(authenticatorKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }
        
        return Ok(new
        {
            message = "2FA enabled",
            authenticatorKey = authenticatorKey,
            qrCodeUrl = $"otpauth://totp/DocumentManagement:{user.Email}?secret={authenticatorKey}&issuer=DocumentManagement"
        });
    }
    
    [Authorize]
    [HttpPost("verify-2fa")]
    public async Task<IActionResult> VerifyTwoFactor([FromBody] Verify2FADto model)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var user = await _userManager.FindByIdAsync(userId ?? string.Empty);
        
        if (user == null)
        {
            return NotFound(new { message = "User not found" });
        }
        
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            model.Code);
        
        if (!isValid)
        {
            return BadRequest(new { message = "Invalid verification code" });
        }
        
        return Ok(new { message = "2FA verified successfully" });
    }
    
    [HttpGet("google-login")]
    public IActionResult GoogleLogin(string returnUrl = "/")
    {
        var redirectUrl = Url.Action("GoogleResponse", "Auth", new { returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
        return Challenge(properties, "Google");
    }
    
    [HttpGet("google-response")]
    public async Task<IActionResult> GoogleResponse(string returnUrl = "/")
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return BadRequest(new { message = "Error loading external login information" });
        }
        
        var signInResult = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: false,
            bypassTwoFactor: true);
        
        if (signInResult.Succeeded)
        {
            var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            if (user != null)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var userClaims = await _userManager.GetClaimsAsync(user);
                var accessToken = _tokenService.GenerateAccessToken(user, roles, userClaims.ToList());
                
                return Ok(new AuthResponseDto
                {
                    AccessToken = accessToken,
                    Email = user.Email ?? string.Empty,
                    FullName = user.FullName ?? string.Empty,
                    Roles = roles.ToList()
                });
            }
        }
        
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        if (string.IsNullOrEmpty(email))
        {
            return BadRequest(new { message = "Email not found in external provider" });
        }
        
        var newUser = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FullName = info.Principal.FindFirstValue(ClaimTypes.Name) ?? email,
            EmailConfirmed = true
        };
        
        var createResult = await _userManager.CreateAsync(newUser);
        if (!createResult.Succeeded)
        {
            return BadRequest(new { errors = createResult.Errors });
        }
        
        await _userManager.AddToRoleAsync(newUser, "Viewer");
        await _userManager.AddLoginAsync(newUser, info);
        
        await _signInManager.SignInAsync(newUser, isPersistent: false);
        
        var newRoles = await _userManager.GetRolesAsync(newUser);
        var newUserClaims = await _userManager.GetClaimsAsync(newUser);
        var newAccessToken = _tokenService.GenerateAccessToken(newUser, newRoles, newUserClaims.ToList());
        
        return Ok(new AuthResponseDto
        {
            AccessToken = newAccessToken,
            Email = newUser.Email ?? string.Empty,
            FullName = newUser.FullName ?? string.Empty,
            Roles = newRoles.ToList()
        });
    }
}

public class ConfirmEmailDto
{
    public string UserId { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
}

public class RefreshTokenDto
{
    public string AccessToken { get; set; } = string.Empty;
    public string? RefreshToken { get; set; }
}

public class Verify2FADto
{
    public string Code { get; set; } = string.Empty;
}
