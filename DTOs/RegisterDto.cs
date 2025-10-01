using System.ComponentModel.DataAnnotations;

namespace DocumentManagementSystem.DTOs;

public class RegisterDto
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    [StringLength(100, MinimumLength = 6)]
    public string Password { get; set; } = string.Empty;
    
    [Required]
    [Compare("Password")]
    public string ConfirmPassword { get; set; } = string.Empty;
    
    [Required]
    [StringLength(100)]
    public string FullName { get; set; } = string.Empty;
    
    public DateTime? DateOfBirth { get; set; }
    
    [StringLength(100)]
    public string? Department { get; set; }
}
