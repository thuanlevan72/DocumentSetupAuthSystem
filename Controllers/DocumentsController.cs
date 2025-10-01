using DocumentManagementSystem.Authorization;
using DocumentManagementSystem.Data;
using DocumentManagementSystem.DTOs;
using DocumentManagementSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace DocumentManagementSystem.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class DocumentsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly IAuthorizationService _authorizationService;
    private readonly IWebHostEnvironment _environment;
    
    public DocumentsController(
        ApplicationDbContext context,
        IAuthorizationService authorizationService,
        IWebHostEnvironment environment)
    {
        _context = context;
        _authorizationService = authorizationService;
        _environment = environment;
    }
    
    [HttpGet]
    [Authorize(Policy = "RequireViewerRole")]
    public async Task<IActionResult> GetAllDocuments()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var isAdmin = User.IsInRole("Admin");
        
        IQueryable<Document> query = _context.Documents
            .Include(d => d.Author)
            .Where(d => !d.IsDeleted);
        
        if (!isAdmin)
        {
            query = query.Where(d => d.AuthorId == userId);
        }
        
        var documents = await query
            .Select(d => new DocumentResponseDto
            {
                Id = d.Id,
                Title = d.Title,
                Description = d.Description,
                FilePath = d.FilePath,
                FileType = d.FileType,
                FileSize = d.FileSize,
                AuthorId = d.AuthorId,
                AuthorName = d.Author.FullName ?? d.Author.Email ?? "Unknown",
                CreatedAt = d.CreatedAt,
                UpdatedAt = d.UpdatedAt
            })
            .ToListAsync();
        
        return Ok(documents);
    }
    
    [HttpGet("{id}")]
    [Authorize(Policy = "RequireViewerRole")]
    public async Task<IActionResult> GetDocument(int id)
    {
        var document = await _context.Documents
            .Include(d => d.Author)
            .FirstOrDefaultAsync(d => d.Id == id && !d.IsDeleted);
        
        if (document == null)
        {
            return NotFound(new { message = "Document not found" });
        }
        
        var authResult = await _authorizationService.AuthorizeAsync(
            User,
            document,
            DocumentOperations.Read);
        
        if (!authResult.Succeeded)
        {
            return Forbid();
        }
        
        var response = new DocumentResponseDto
        {
            Id = document.Id,
            Title = document.Title,
            Description = document.Description,
            FilePath = document.FilePath,
            FileType = document.FileType,
            FileSize = document.FileSize,
            AuthorId = document.AuthorId,
            AuthorName = document.Author.FullName ?? document.Author.Email ?? "Unknown",
            CreatedAt = document.CreatedAt,
            UpdatedAt = document.UpdatedAt
        };
        
        return Ok(response);
    }
    
    [HttpPost]
    [Authorize(Policy = "RequireEditorRole")]
    [Authorize(Policy = "Over21")]
    public async Task<IActionResult> CreateDocument([FromForm] CreateDocumentDto model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }
        
        var uploadsFolder = Path.Combine(_environment.ContentRootPath, "uploads");
        if (!Directory.Exists(uploadsFolder))
        {
            Directory.CreateDirectory(uploadsFolder);
        }
        
        var uniqueFileName = $"{Guid.NewGuid()}_{model.File.FileName}";
        var filePath = Path.Combine(uploadsFolder, uniqueFileName);
        
        using (var stream = new FileStream(filePath, FileMode.Create))
        {
            await model.File.CopyToAsync(stream);
        }
        
        var document = new Document
        {
            Title = model.Title,
            Description = model.Description,
            FilePath = filePath,
            FileType = Path.GetExtension(model.File.FileName),
            FileSize = model.File.Length,
            AuthorId = userId
        };
        
        _context.Documents.Add(document);
        await _context.SaveChangesAsync();
        
        var author = await _context.Users.FindAsync(userId);
        
        var response = new DocumentResponseDto
        {
            Id = document.Id,
            Title = document.Title,
            Description = document.Description,
            FilePath = document.FilePath,
            FileType = document.FileType,
            FileSize = document.FileSize,
            AuthorId = document.AuthorId,
            AuthorName = author?.FullName ?? author?.Email ?? "Unknown",
            CreatedAt = document.CreatedAt
        };
        
        return CreatedAtAction(nameof(GetDocument), new { id = document.Id }, response);
    }
    
    [HttpPut("{id}")]
    [Authorize(Policy = "RequireEditorRole")]
    public async Task<IActionResult> UpdateDocument(int id, [FromBody] UpdateDocumentDto model)
    {
        var document = await _context.Documents
            .FirstOrDefaultAsync(d => d.Id == id && !d.IsDeleted);
        
        if (document == null)
        {
            return NotFound(new { message = "Document not found" });
        }
        
        var authResult = await _authorizationService.AuthorizeAsync(
            User,
            document,
            DocumentOperations.Update);
        
        if (!authResult.Succeeded)
        {
            return Forbid();
        }
        
        if (!string.IsNullOrEmpty(model.Title))
        {
            document.Title = model.Title;
        }
        
        if (model.Description != null)
        {
            document.Description = model.Description;
        }
        
        document.UpdatedAt = DateTime.UtcNow;
        
        await _context.SaveChangesAsync();
        
        return Ok(new { message = "Document updated successfully", documentId = document.Id });
    }
    
    [HttpDelete("{id}")]
    [Authorize(Policy = "RequireEditorRole")]
    public async Task<IActionResult> DeleteDocument(int id)
    {
        var document = await _context.Documents
            .FirstOrDefaultAsync(d => d.Id == id && !d.IsDeleted);
        
        if (document == null)
        {
            return NotFound(new { message = "Document not found" });
        }
        
        var authResult = await _authorizationService.AuthorizeAsync(
            User,
            document,
            DocumentOperations.Delete);
        
        if (!authResult.Succeeded)
        {
            return Forbid();
        }
        
        document.IsDeleted = true;
        await _context.SaveChangesAsync();
        
        return Ok(new { message = "Document deleted successfully" });
    }
    
    [HttpGet("download/{id}")]
    public async Task<IActionResult> DownloadDocument(int id)
    {
        var document = await _context.Documents
            .FirstOrDefaultAsync(d => d.Id == id && !d.IsDeleted);
        
        if (document == null)
        {
            return NotFound(new { message = "Document not found" });
        }
        
        var authResult = await _authorizationService.AuthorizeAsync(
            User,
            document,
            DocumentOperations.Read);
        
        if (!authResult.Succeeded)
        {
            return Forbid();
        }
        
        if (!System.IO.File.Exists(document.FilePath))
        {
            return NotFound(new { message = "File not found on server" });
        }
        
        var memory = new MemoryStream();
        using (var stream = new FileStream(document.FilePath, FileMode.Open))
        {
            await stream.CopyToAsync(memory);
        }
        memory.Position = 0;
        
        var fileName = Path.GetFileName(document.FilePath);
        var contentType = GetContentType(document.FileType ?? string.Empty);
        
        return File(memory, contentType, fileName);
    }
    
    [HttpGet("department")]
    [Authorize(Policy = "DepartmentPolicy")]
    public async Task<IActionResult> GetDocumentsByDepartment()
    {
        var department = User.FindFirst("department")?.Value;
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        var documents = await _context.Documents
            .Include(d => d.Author)
            .Where(d => !d.IsDeleted && d.Author.Department == department)
            .Select(d => new DocumentResponseDto
            {
                Id = d.Id,
                Title = d.Title,
                Description = d.Description,
                FilePath = d.FilePath,
                FileType = d.FileType,
                FileSize = d.FileSize,
                AuthorId = d.AuthorId,
                AuthorName = d.Author.FullName ?? d.Author.Email ?? "Unknown",
                CreatedAt = d.CreatedAt,
                UpdatedAt = d.UpdatedAt
            })
            .ToListAsync();
        
        return Ok(new
        {
            department = department,
            documentCount = documents.Count,
            documents = documents
        });
    }
    
    private static string GetContentType(string fileExtension)
    {
        return fileExtension.ToLowerInvariant() switch
        {
            ".pdf" => "application/pdf",
            ".doc" => "application/msword",
            ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls" => "application/vnd.ms-excel",
            ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".txt" => "text/plain",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            _ => "application/octet-stream"
        };
    }
}
