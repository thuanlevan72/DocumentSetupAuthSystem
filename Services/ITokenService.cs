using DocumentManagementSystem.Models;
using System.Security.Claims;

namespace DocumentManagementSystem.Services;

public interface ITokenService
{
    string GenerateAccessToken(ApplicationUser user, IList<string> roles, IList<Claim> claims);
    string GenerateRefreshToken();
    string HashRefreshToken(string token);
    ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
}
