using DocumentManagementSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace DocumentManagementSystem.Authorization;

public class DocumentAuthorizationHandler : AuthorizationHandler<OperationAuthorizationRequirement, Document>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Document resource)
    {
        if (context.User == null || resource == null)
        {
            return Task.CompletedTask;
        }
        
        if (context.User.IsInRole("Admin"))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }
        
        if (requirement.Name == "Read")
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }
        
        var userId = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        
        if (userId == resource.AuthorId)
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}

public static class DocumentOperations
{
    public static OperationAuthorizationRequirement Create = new() { Name = "Create" };
    public static OperationAuthorizationRequirement Read = new() { Name = "Read" };
    public static OperationAuthorizationRequirement Update = new() { Name = "Update" };
    public static OperationAuthorizationRequirement Delete = new() { Name = "Delete" };
}
