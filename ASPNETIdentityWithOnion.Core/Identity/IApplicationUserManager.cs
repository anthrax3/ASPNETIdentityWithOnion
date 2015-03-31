using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using ASPNETIdentityWithOnion.Core.DomainModels.Identity;

namespace ASPNETIdentityWithOnion.Core.Identity
{
    public interface IApplicationUserManager : IDisposable
    {
        string ApplicationCookie { get; }
        string ExternalBearer { get; }
        string ExternalCookie { get; }
        string TwoFactorCookie { get; }
        string TwoFactorRememberBrowserCookie { get; }
        Task<ApplicationIdentityResult> AccessFailedAsync(string userId);
        Task<ApplicationIdentityResult> AddClaimAsync(string userId, Claim claim);
        Task<ApplicationIdentityResult> AddLoginAsync(string userId, ApplicationUserLoginInfo login);
        Task<ApplicationIdentityResult> AddToRoleAsync(string userId, string role);
        ApplicationIdentityResult AddToRole(string userId, string role);
        Task<ApplicationIdentityResult> AddPasswordAsync(string userId, string password);
        Task<ApplicationIdentityResult> AddUserToRolesAsync(string userId, IList<string> roles);
        Task<ApplicationIdentityResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword);
        Task<ApplicationIdentityResult> ChangePhoneNumberAsync(string userId, string phoneNumber, string token);
        void Challenge(string redirectUri, string xsrfKey, string userId, params string[] authenticationTypes);
        Task<bool> CheckPasswordAsync(AppUser user, string password);
        Task<ApplicationIdentityResult> ConfirmEmailAsync(string userId, string token);
        Task<ApplicationIdentityResult> CreateAsync(AppUser user);
        Task<ApplicationIdentityResult> CreateAsync(AppUser user, string password);
        ClaimsIdentity CreateIdentity(AppUser user, string authenticationType);
        Task<ClaimsIdentity> CreateIdentityAsync(AppUser user, string authenticationType);
        ApplicationIdentityResult Create(AppUser user);
        ApplicationIdentityResult Create(AppUser user, string password);
        ClaimsIdentity CreateTwoFactorRememberBrowserIdentity(string userId);
        Task<ApplicationIdentityResult> DeleteAsync(string userId);
        Task<SignInStatus> ExternalSignIn(ApplicationExternalLoginInfo loginInfo, bool isPersistent);
        Task<AppUser> FindAsync(ApplicationUserLoginInfo login);
        Task<AppUser> FindAsync(string userName, string password);
        Task<AppUser> FindByEmailAsync(string email);
        AppUser FindById(string userId);
        Task<AppUser> FindByIdAsync(string userId);
        Task<AppUser> FindByNameAsync(string userName);
        AppUser FindByName(string userName);
        Task<string> GenerateChangePhoneNumberTokenAsync(string userId, string phoneNumber);
        Task<string> GenerateEmailConfirmationTokenAsync(string userId);
        Task<string> GeneratePasswordResetTokenAsync(string userId);
        Task<string> GenerateTwoFactorTokenAsync(string userId, string twoFactorProvider);
        Task<string> GenerateUserTokenAsync(string purpose, string userId);
        Task<int> GetAccessFailedCountAsync(string userId);
        Task<IList<Claim>> GetClaimsAsync(string userId);
        Task<string> GetEmailAsync(string userId);
        IEnumerable<ApplicationAuthenticationDescription> GetExternalAuthenticationTypes();
        Task<ClaimsIdentity> GetExternalIdentityAsync(string externalAuthenticationType);
        ApplicationExternalLoginInfo GetExternalLoginInfo();
        ApplicationExternalLoginInfo GetExternalLoginInfo(string xsrfKey, string expectedValue);
        Task<ApplicationExternalLoginInfo> GetExternalLoginInfoAsync();
        Task<ApplicationExternalLoginInfo> GetExternalLoginInfoAsync(string xsrfKey, string expectedValue);
        Task<bool> GetLockoutEnabledAsync(string userId);
        Task<DateTimeOffset> GetLockoutEndDateAsync(string userId);
        IList<ApplicationUserLoginInfo> GetLogins(string userId);
        Task<IList<ApplicationUserLoginInfo>> GetLoginsAsync(string userId);
        Task<string> GetPhoneNumberAsync(string userId);
        Task<IList<string>> GetRolesAsync(string userId);
        IList<string> GetRoles(string userId);
        Task<string> GetSecurityStampAsync(string userId);
        Task<bool> GetTwoFactorEnabledAsync(string userId);
        Task<IList<string>> GetValidTwoFactorProvidersAsync(string userId);
        Task<string> GetVerifiedUserIdAsync();
        Task<bool> HasBeenVerified();
        Task<bool> HasPasswordAsync(string userId);
        Task<bool> IsEmailConfirmedAsync(string userId);
        Task<bool> IsInRoleAsync(string userId, string role);
        Task<bool> IsLockedOutAsync(string userId);
        Task<bool> IsPhoneNumberConfirmedAsync(string userId);
        Task<ApplicationIdentityResult> NotifyTwoFactorTokenAsync(string userId, string twoFactorProvider, string token);
        Task<SignInStatus> PasswordSignIn(string userName, string password, bool isPersistent, bool shouldLockout);
        Task<ApplicationIdentityResult> RemoveClaimAsync(string userId, Claim claim);
        Task<ApplicationIdentityResult> RemoveFromRoleAsync(string userId, string role);
        Task<ApplicationIdentityResult> RemoveLoginAsync(string userId, ApplicationUserLoginInfo login);
        Task<ApplicationIdentityResult> RemovePasswordAsync(string userId);
        Task<ApplicationIdentityResult> RemoveUserFromRolesAsync(string userId, IList<string> roles);
        Task<ApplicationIdentityResult> ResetAccessFailedCountAsync(string userId);
        Task<ApplicationIdentityResult> ResetPasswordAsync(string userId, string token, string newPassword);
        Task SendEmailAsync(string userId, string subject, string body);
        Task SendSmsAsync(string userId, string message);
        Task SendSmsAsync(ApplicationMessage message);
        Task<bool> SendTwoFactorCode(string provider);
        Task<ApplicationIdentityResult> SetEmailAsync(string userId, string email);
        Task<ApplicationIdentityResult> SetLockoutEnabledAsync(string userId, bool enabled);
        ApplicationIdentityResult SetLockoutEnabled(string userId, bool enabled);
        Task<ApplicationIdentityResult> SetLockoutEndDateAsync(string userId, DateTimeOffset lockoutEnd);
        Task<ApplicationIdentityResult> SetPhoneNumberAsync(string userId, string phoneNumber);
        Task<ApplicationIdentityResult> SetTwoFactorEnabledAsync(string userId, bool enabled);
        Task<SignInStatus> SignInOrTwoFactor(AppUser user, bool isPersistent);
        void SignIn(params ClaimsIdentity[] identities);
        void SignIn(bool isPersistent, params ClaimsIdentity[] identities);
        void SignIn(AppUser user, bool isPersistent, bool rememberBrowser);
        Task SignInAsync(AppUser user, bool isPersistent, bool rememberBrowser);
        void SignOut(params string[] authenticationTypes);
        Task<bool> TwoFactorBrowserRememberedAsync(string userId);
        Task<SignInStatus> TwoFactorSignIn(string provider, string code, bool isPersistent, bool rememberBrowser);
        Task<ApplicationIdentityResult> UpdateAsync(string userId);
        Task<ApplicationIdentityResult> UpdateSecurityStampAsync(string userId);
        IEnumerable<AppUser> GetUsers();
        Task<IEnumerable<AppUser>> GetUsersAsync();
        Task<bool> VerifyChangePhoneNumberTokenAsync(string userId, string token, string phoneNumber);
        Task<bool> VerifyTwoFactorTokenAsync(string userId, string twoFactorProvider, string token);
        Task<bool> VerifyUserTokenAsync(string userId, string purpose, string token);
        
    }
}