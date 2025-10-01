using System.ComponentModel.DataAnnotations;

namespace DocumentManagementSystem.DTOs;

public class CreateDocumentDto
{
    [Required]
    [StringLength(200)]
    public string Title { get; set; } = string.Empty;
    
    public string? Description { get; set; }
    
    [Required]
    public IFormFile File { get; set; } = null!;
}

public class UpdateDocumentDto
{
    [StringLength(200)]
    public string? Title { get; set; }
    
    public string? Description { get; set; }
}

public class DocumentResponseDto
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string? FileType { get; set; }
    public long FileSize { get; set; }
    public string AuthorId { get; set; } = string.Empty;
    public string AuthorName { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
}
