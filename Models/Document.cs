using System.ComponentModel.DataAnnotations;

namespace DocumentManagementSystem.Models;

public class Document
{
    public int Id { get; set; }
    
    [Required]
    [StringLength(200)]
    public string Title { get; set; } = string.Empty;
    
    public string? Description { get; set; }
    
    [Required]
    public string FilePath { get; set; } = string.Empty;
    
    public string? FileType { get; set; }
    
    public long FileSize { get; set; }
    
    [Required]
    public string AuthorId { get; set; } = string.Empty;
    
    public ApplicationUser Author { get; set; } = null!;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? UpdatedAt { get; set; }
    
    public bool IsDeleted { get; set; } = false;
}
