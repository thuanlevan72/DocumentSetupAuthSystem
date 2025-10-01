# Document Management System

## Overview

Hệ thống quản lý tài liệu (Document Management System) được xây dựng với ASP.NET Core 8.0, cung cấp khả năng lưu trữ và quản lý tài liệu an toàn với xác thực và phân quyền người dùng đầy đủ. Hệ thống hỗ trợ cả JWT authentication, Cookie-based authentication, Google OAuth2, Two-Factor Authentication (2FA), và nhiều mức độ phân quyền khác nhau.

## User Preferences

Preferred communication style: Simple, everyday language (Tiếng Việt)

## System Architecture

### Backend Framework
- **Technology**: ASP.NET Core 8.0 Web API
- **Key Features**: RESTful API với Swagger/OpenAPI documentation

### Authentication (Xác Thực)

#### 1. JWT Bearer Authentication (API)
- **Access Token**: Hết hạn sau 15 phút
- **Refresh Token**: Hết hạn sau 7 ngày, hỗ trợ token rotation
- **Token Claims**: 
  - User ID (sub, NameIdentifier)
  - Email
  - Full Name
  - Age (tính từ ngày sinh)
  - Department (phòng ban)
  - Roles (vai trò)

#### 2. Cookie-Based Authentication (Web UI)
- Cấu hình cho web application với HttpOnly, Secure cookies
- Session timeout: 7 ngày với sliding expiration

#### 3. Google OAuth2/OpenID Connect
- Social login integration
- Automatic user creation khi đăng nhập lần đầu
- Endpoints: `/api/auth/google-login`, `/api/auth/google-response`

#### 4. Two-Factor Authentication (2FA)
- TOTP (Time-based One-Time Password) support
- Authenticator app integration
- Endpoints: `/api/auth/enable-2fa`, `/api/auth/verify-2fa`

### Authorization (Phân Quyền)

#### 1. Role-Based Access Control (RBAC)
- **Admin**: Toàn quyền trên hệ thống, xem/sửa/xóa tất cả documents
- **Editor**: Upload và quản lý documents của mình (yêu cầu trên 21 tuổi)
- **Viewer**: Chỉ xem documents

**Seeded Users**:
- `admin@dms.com` / `Admin@123` - Admin role, 35 tuổi, IT department
- `editor@dms.com` / `Editor@123` - Editor role, 30 tuổi, Content department
- `viewer@dms.com` / `Viewer@123` - Viewer role, 20 tuổi, Operations department

#### 2. Claims-Based Authorization
- **Department Claim**: Phân quyền theo phòng ban
- **Policy**: `DepartmentPolicy` - Yêu cầu user phải có claim "department"
- **Endpoint**: `GET /api/documents/department` - Lấy documents của cùng phòng ban

#### 3. Policy-Based Authorization
- **Over21 Policy**: Chỉ cho phép người trên 21 tuổi upload documents
- **MinimumAgeRequirement**: Custom requirement handler kiểm tra tuổi từ claim
- **Áp dụng**: `POST /api/documents` - Tạo document mới

#### 4. Resource-Based Authorization
- **DocumentAuthorizationHandler**: Kiểm tra ownership của document
- **Quyền**:
  - **Read**: Tất cả authenticated users
  - **Update/Delete**: Chỉ author hoặc Admin
- **DocumentOperations**: Create, Read, Update, Delete

### API Endpoints

#### Authentication Endpoints (`/api/auth`)
- `POST /register` - Đăng ký user mới
- `POST /confirm-email` - Xác nhận email
- `POST /login` - Đăng nhập (JWT + Refresh Token)
- `POST /refresh-token` - Làm mới access token
- `POST /logout` - Đăng xuất (revoke refresh tokens)
- `POST /enable-2fa` - Bật 2FA
- `POST /verify-2fa` - Xác minh 2FA code
- `GET /google-login` - Bắt đầu Google OAuth flow
- `GET /google-response` - Callback từ Google OAuth

#### Document Endpoints (`/api/documents`)
- `GET /api/documents` - Lấy danh sách documents (Admin: tất cả, User: của mình)
- `GET /api/documents/{id}` - Xem chi tiết document
- `GET /api/documents/department` - Documents của cùng phòng ban (DepartmentPolicy)
- `POST /api/documents` - Upload document mới (Editor role + Over21 policy)
- `PUT /api/documents/{id}` - Cập nhật document (Resource-based: owner hoặc Admin)
- `DELETE /api/documents/{id}` - Xóa document (Resource-based: owner hoặc Admin)
- `GET /api/documents/download/{id}` - Download file

### Data Storage
- **Entity Framework Core** với **InMemory Database** (development)
- **Models**:
  - `ApplicationUser`: Extends IdentityUser với FullName, DateOfBirth, Department
  - `Document`: Title, Description, FilePath, FileType, FileSize, AuthorId
  - `RefreshToken`: Token (plaintext - TODO: hash), UserId, ExpiresAt, IsRevoked
- **File Storage**: Local `uploads/` directory với GUID-based filenames

### Security Best Practices

#### Implemented ✅
1. **Password Hashing**: ASP.NET Core Identity với cryptographic key derivation
2. **Email Confirmation**: Required trước khi login
3. **JWT Token Validation**: Issuer, Audience, Lifetime, Signing Key
4. **Access Token Expiration**: 15 phút (short-lived)
5. **Refresh Token Rotation**: Old token bị revoke khi refresh
6. **HttpOnly Cookies**: Refresh token stored trong HttpOnly cookie
7. **CORS**: Development cho phép tất cả, Production chỉ trusted origins
8. **HTTPS**: RequireHttpsMetadata enabled cho production
9. **Configuration Security**: JWT secrets required (throw exception nếu thiếu)
10. **Multiple Authorization Levels**: RBAC + Claims + Policy + Resource-based

#### TODO / Improvements 🔧
1. **Hash Refresh Tokens**: Method đã tạo (`HashRefreshToken`) nhưng chưa integrate vào flow
2. **HTTPS Redirection**: Thêm `UseHttpsRedirection()` cho production
3. **Web UI**: Cookie authentication đã config nhưng chưa có Controllers/Views
4. **Google OAuth**: Placeholder credentials cần thay bằng real credentials
5. **Department Filter**: Có thể cải thiện query performance với index

## External Dependencies

### NuGet Packages (8.0.11)
- Microsoft.AspNetCore.Identity.EntityFrameworkCore
- Microsoft.EntityFrameworkCore.InMemory
- Microsoft.AspNetCore.Authentication.JwtBearer
- Microsoft.AspNetCore.Authentication.Google
- Microsoft.AspNetCore.OpenApi (8.0.18)
- Swashbuckle.AspNetCore (6.6.2)

### Configuration Requirements

#### appsettings.json
```json
{
  "JwtSettings": {
    "SecretKey": "YourSecretKey",
    "Issuer": "DocumentManagementSystem",
    "Audience": "DocumentManagementAPI",
    "AccessTokenExpirationMinutes": "15",
    "RefreshTokenExpirationDays": "7"
  },
  "Authentication": {
    "Google": {
      "ClientId": "your-client-id",
      "ClientSecret": "your-client-secret"
    }
  }
}
```

## Testing Results

Đã test thành công:
1. ✅ Login với admin/editor/viewer accounts
2. ✅ JWT token chứa đầy đủ claims (age, department, roles)
3. ✅ RBAC: Admin xem tất cả, Editor/Viewer chỉ xem của mình
4. ✅ Policy-based (Over21): Editor (30 tuổi) upload được, Viewer (20 tuổi) bị từ chối (403)
5. ✅ Resource-based: Editor chỉ update/delete documents của mình, Admin update/delete tất cả
6. ✅ Claims-based (DepartmentPolicy): `/api/documents/department` hoạt động với Admin (IT dept)
7. ✅ Refresh token rotation: Old token bị revoke khi refresh
8. ✅ Email confirmation: Required trước khi login

## How to Run

```bash
dotnet run
```

Server sẽ chạy tại: `http://0.0.0.0:5000`
Swagger UI: `http://localhost:5000/swagger`

## Production Deployment Checklist

1. Thay InMemory database bằng persistent database (SQL Server, PostgreSQL)
2. Set JWT SecretKey, Google OAuth credentials trong environment variables
3. Configure AllowedOrigins cho CORS
4. Enable HTTPS và set `UseHttpsRedirection()`
5. Integrate `HashRefreshToken` vào AuthController
6. Set up reverse proxy (nginx, IIS) cho TLS termination
7. Enable logging và monitoring
8. Regular security audits
