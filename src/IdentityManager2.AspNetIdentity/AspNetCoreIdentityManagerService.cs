using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityManager2.Core;
using IdentityManager2.Core.Metadata;
using IdentityManager2.Extensions;
using Microsoft.AspNetCore.Identity;

namespace IdentityManager2.AspNetIdentity
{
    public class AspNetCoreIdentityManagerService<TUser, TUserKey, TRole, TRoleKey> : IIdentityManagerService
        where TUser : IdentityUser<TUserKey>, new()
        where TRole : IdentityRole<TRoleKey>, new()
        where TUserKey : IEquatable<TUserKey>
        where TRoleKey : IEquatable<TRoleKey>
    {
        public string RoleClaimType { get; set; }

        protected readonly UserManager<TUser> UserManager;
        protected readonly RoleManager<TRole> RoleManager;
        protected readonly Func<Task<IdentityManagerMetadata>> MetadataFunc;

        internal AspNetCoreIdentityManagerService(UserManager<TUser> userManager, RoleManager<TRole> roleManager)
        {
            this.UserManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            this.RoleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));

            if (!userManager.SupportsQueryableUsers) throw new InvalidOperationException("UserManager must support queryable users.");

            var email = userManager.Options.Tokens.EmailConfirmationTokenProvider; // TODO: and for rest...
            if (!userManager.Options.Tokens.ProviderMap.ContainsKey(email)) { }

            RoleClaimType = Constants.ClaimTypes.Role;
        }

        public AspNetCoreIdentityManagerService(
            UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            bool includeAccountProperties = true)
            : this(userManager, roleManager)
        {
            MetadataFunc = () => GetStandardMetadata(includeAccountProperties);
        }

        public AspNetCoreIdentityManagerService(
            UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            IdentityManagerMetadata metadata)
            : this(userManager, roleManager, () => Task.FromResult(metadata))
        {
        }

        public AspNetCoreIdentityManagerService(
            UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            Func<Task<IdentityManagerMetadata>> metadataFunc)
            : this(userManager, roleManager)
        {
            this.MetadataFunc = metadataFunc;
        }

        public Task<IdentityManagerMetadata> GetMetadataAsync() => MetadataFunc();

        public async Task<IdentityManagerResult<CreateResult>> CreateUserAsync(IEnumerable<PropertyValue> properties)
        {
            var usernameClaim = properties.Single(x => x.Type == Constants.ClaimTypes.Username);
            var passwordClaim = properties.Single(x => x.Type == Constants.ClaimTypes.Password);

            var username = usernameClaim.Value;
            var password = passwordClaim.Value;

            var exclude = new[] { Constants.ClaimTypes.Username, Constants.ClaimTypes.Password };
            var otherProperties = properties.Where(x => !exclude.Contains(x.Type)).ToArray();

            var metadata = await GetMetadataAsync();
            var createProps = metadata.UserMetadata.GetCreateProperties();

            var user = new TUser { UserName = username };
            foreach (var prop in otherProperties)
            {
                var propertyResult = await SetUserProperty(createProps, user, prop.Type, prop.Value);
                if (!propertyResult.IsSuccess)
                {
                    return new IdentityManagerResult<CreateResult>(propertyResult.Errors.ToArray());
                }
            }

            var result = await UserManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
            }

            return new IdentityManagerResult<CreateResult>(new CreateResult { Subject = user.Id.ToString() });
        }

        public async Task<IdentityManagerResult> DeleteUserAsync(string subject)
        {
            var user = await UserManager.FindByIdAsync(subject);
            if (user == null) return new IdentityManagerResult("Invalid subject");

            var result = await UserManager.DeleteAsync(user);
            if (!result.Succeeded) return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult<QueryResult<UserSummary>>> QueryUsersAsync(string filter, int start, int count)
        {
            var query =
                from user in UserManager.Users
                orderby user.UserName
                select user;

            if (!string.IsNullOrWhiteSpace(filter))
            {
                query =
                    from user in query
                    where user.UserName.Contains(filter)
                    orderby user.UserName
                    select user;
            }

            var total = query.Count();
            var users = query.Skip(start).Take(count).ToArray();

            var items = new List<UserSummary>();
            foreach (var user in users)
            {
                items.Add(new UserSummary
                {
                    Subject = user.Id.ToString(),
                    Username = user.UserName,
                    Name = await DisplayNameFromUser(user)
                });
            }

            var result = new QueryResult<UserSummary>
            {
                Start = start,
                Count = count,
                Total = total,
                Filter = filter,
                Items = items
            };

            return new IdentityManagerResult<QueryResult<UserSummary>>(result);
        }

        public async Task<IdentityManagerResult<UserDetail>> GetUserAsync(string subject)
        {
            var user = await UserManager.FindByIdAsync(subject);
            if (user == null) return new IdentityManagerResult<UserDetail>((UserDetail)null);

            var result = new UserDetail
            {
                Subject = subject,
                Username = user.UserName,
                Name = await DisplayNameFromUser(user),
            };

            var metadata = await GetMetadataAsync();

            var props = new List<PropertyValue>();
            foreach (var prop in metadata.UserMetadata.UpdateProperties)
            {
                props.Add(new PropertyValue
                {
                    Type = prop.Type,
                    Value = await GetUserProperty(prop, user)
                });
            }

            result.Properties = props.ToArray();

            if (UserManager.SupportsUserClaim)
            {
                var userClaims = await UserManager.GetClaimsAsync(user);
                var claims = new List<ClaimValue>();
                if (userClaims != null)
                {
                    claims.AddRange(userClaims.Select(x => new ClaimValue { Type = x.Type, Value = x.Value }));
                }
                result.Claims = claims.ToArray();
            }

            return new IdentityManagerResult<UserDetail>(result);
        }

        public async Task<IdentityManagerResult> SetUserPropertyAsync(string subject, string type, string value)
        {
            var user = await UserManager.FindByIdAsync(subject);
            if (user == null) return new IdentityManagerResult("Invalid subject");

            var errors = ValidateUserProperty(type, value).ToList();
            if (errors.Any()) return new IdentityManagerResult(errors.ToArray());

            var metadata = await GetMetadataAsync();
            var propResult = await SetUserProperty(metadata.UserMetadata.UpdateProperties, user, type, value);
            if (!propResult.IsSuccess) return propResult;

            var result = await UserManager.UpdateAsync(user);
            if (!result.Succeeded) return new IdentityManagerResult(result.Errors.Select(x => x.Description).ToArray());

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult> AddUserClaimAsync(string subject, string type, string value)
        {
            var user = await UserManager.FindByIdAsync(subject);
            if (user == null) return new IdentityManagerResult("Invalid subject");

            var existingClaims = await UserManager.GetClaimsAsync(user);
            if (!existingClaims.Any(x => x.Type == type && x.Value == value))
            {
                var result = await UserManager.AddClaimAsync(user, new Claim(type, value));
                if (!result.Succeeded) return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
            }

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult> RemoveUserClaimAsync(string subject, string type, string value)
        {
            var user = await UserManager.FindByIdAsync(subject);
            if (user == null) return new IdentityManagerResult("Invalid subject");

            var result = await UserManager.RemoveClaimAsync(user, new Claim(type, value));
            if (!result.Succeeded) return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult<CreateResult>> CreateRoleAsync(IEnumerable<PropertyValue> properties)
        {
            ValidateSupportsRoles();

            var nameClaim = properties.Single(x => x.Type == Constants.ClaimTypes.Name);
            var name = nameClaim.Value;

            var exclude = new[] { Constants.ClaimTypes.Name };
            var otherProperties = properties.Where(x => !exclude.Contains(x.Type)).ToArray();

            var metadata = await GetMetadataAsync();
            var createProps = metadata.RoleMetadata.GetCreateProperties();

            var role = new TRole { Name = name };
            foreach (var prop in otherProperties)
            {
                var roleResult = await SetRoleProperty(createProps, role, prop.Type, prop.Value);
                if (!roleResult.IsSuccess)
                {
                    return new IdentityManagerResult<CreateResult>(roleResult.Errors.ToArray());
                }
            }

            var result = await RoleManager.CreateAsync(role);
            if (!result.Succeeded) return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());

            return new IdentityManagerResult<CreateResult>(new CreateResult { Subject = role.Id.ToString() });
        }

        public async Task<IdentityManagerResult> DeleteRoleAsync(string subject)
        {
            ValidateSupportsRoles();

            var role = await RoleManager.FindByIdAsync(subject);
            if (role == null) return new IdentityManagerResult("Invalid subject");

            var result = await RoleManager.DeleteAsync(role);
            if (!result.Succeeded) return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());

            return IdentityManagerResult.Success;
        }

        public Task<IdentityManagerResult<QueryResult<RoleSummary>>> QueryRolesAsync(string filter, int start, int count)
        {
            ValidateSupportsRoles();

            if (start < 0) start = 0;
            if (count < 0) count = int.MaxValue;

            var query =
                from role in RoleManager.Roles
                orderby role.Name
                select role;

            if (!string.IsNullOrWhiteSpace(filter))
            {
                query =
                    from role in query
                    where role.Name.Contains(filter)
                    orderby role.Name
                    select role;
            }

            var total = query.Count();
            var roles = query.Skip(start).Take(count).ToArray();

            var result = new QueryResult<RoleSummary>
            {
                Start = start,
                Count = count,
                Total = total,
                Filter = filter,
                Items = roles.Select(x =>
                {
                    var user = new RoleSummary
                    {
                        Subject = x.Id.ToString(),
                        Name = x.Name,
                        // TODO: Role Description
                    };

                    return user;
                }).ToArray()
            };

            return Task.FromResult(new IdentityManagerResult<QueryResult<RoleSummary>>(result));
        }

        public async Task<IdentityManagerResult<RoleDetail>> GetRoleAsync(string subject)
        {
            ValidateSupportsRoles();

            var role = await RoleManager.FindByIdAsync(subject);
            if (role == null) return new IdentityManagerResult<RoleDetail>((RoleDetail)null);

            var result = new RoleDetail
            {
                Subject = subject,
                Name = role.Name,
                // TODO: Role Description
            };

            var metadata = await GetMetadataAsync();

            var props = new List<PropertyValue>();
            foreach (var prop in metadata.RoleMetadata.UpdateProperties)
            {
                props.Add(new PropertyValue
                {
                    Type = prop.Type,
                    Value = await GetRoleProperty(prop, role)
                });
            }

            result.Properties = props.ToArray();

            return new IdentityManagerResult<RoleDetail>(result);
        }

        public async Task<IdentityManagerResult> SetRolePropertyAsync(string subject, string type, string value)
        {
            ValidateSupportsRoles();

            var role = await RoleManager.FindByIdAsync(subject);
            if (role == null) return new IdentityManagerResult("Invalid subject");

            var errors = ValidateRoleProperty(type, value).ToList();
            if (errors.Any()) return new IdentityManagerResult(errors.ToArray());

            var metadata = await GetMetadataAsync();
            var result = await SetRoleProperty(metadata.RoleMetadata.UpdateProperties, role, type, value);
            if (!result.IsSuccess) return result;

            var updateResult = await RoleManager.UpdateAsync(role);
            if (!updateResult.Succeeded) return new IdentityManagerResult(result.Errors.ToArray());

            return IdentityManagerResult.Success;
        }

        public virtual Task<IdentityManagerMetadata> GetStandardMetadata(bool includeAccountProperties = true)
        {
            var update = new List<PropertyMetadata>();
            if (UserManager.SupportsUserPassword)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Password, u => Task.FromResult<string>(null), SetPassword, "Password", PropertyDataType.Password, true));
            }
            if (UserManager.SupportsUserEmail)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Email, u => GetEmail(u), SetEmail, "Email", PropertyDataType.Email));
            }
            if (UserManager.SupportsUserPhoneNumber)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Phone, u => GetPhone(u), SetPhone, "Phone", PropertyDataType.String));
            }
            if (UserManager.SupportsUserTwoFactor)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, bool>("two_factor", u => GetTwoFactorEnabled(u), SetTwoFactorEnabled, "Two Factor Enabled", PropertyDataType.Boolean));
            }
            if (UserManager.SupportsUserLockout)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, bool>("locked_enabled", GetLockoutEnabled, (user1, enabled) => SetLockoutEnabled(user1, enabled), "Lockout Enabled", PropertyDataType.Boolean));
                update.Add(PropertyMetadata.FromFunctions<TUser, bool>("locked", GetLockedOut, (user1, locked) => SetLockedOut(user1, locked), "Locked Out", PropertyDataType.Boolean));
            }

            if (includeAccountProperties)
            {
                update.AddRange(PropertyMetadata.FromType<TUser>());
            }

            var create = new List<PropertyMetadata>();
            create.Add(PropertyMetadata.FromProperty<TUser>(x => x.UserName, name: Constants.ClaimTypes.Username, required: true));
            create.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Password, u => Task.FromResult<string>(null), SetPassword, "Password", PropertyDataType.Password, true));

            var user = new UserMetadata
            {
                SupportsCreate = true,
                SupportsDelete = true,
                SupportsClaims = UserManager.SupportsUserClaim,
                CreateProperties = create,
                UpdateProperties = update
            };

            var role = new RoleMetadata
            {
                RoleClaimType = RoleClaimType,
                SupportsCreate = true,
                SupportsDelete = true,
                CreateProperties = new[] {
                    PropertyMetadata.FromProperty<TRole>(x=>x.Name, name: Constants.ClaimTypes.Name, required: true),
                }
            };

            var meta = new IdentityManagerMetadata
            {
                UserMetadata = user,
                RoleMetadata = role
            };
            return Task.FromResult(meta);
        }

        public virtual PropertyMetadata GetMetadataForClaim(string type, string name = null, PropertyDataType dataType = PropertyDataType.String, bool required = false)
        {
            return PropertyMetadata.FromFunctions(type, GetForClaim(type), SetForClaim(type), name, dataType, required);
        }
        public virtual Func<TUser, Task<string>> GetForClaim(string type)
        {
            return async user => (await UserManager.GetClaimsAsync(user)).Where(x => x.Type == type).Select(x => x.Value).FirstOrDefault();
        }
        public virtual Func<TUser, string, Task<IdentityManagerResult>> SetForClaim(string type)
        {
            return async (user, value) =>
            {
                var claims = await UserManager.GetClaimsAsync(user);
                claims = claims.Where(x => x.Type == type).ToArray();

                foreach (var claim in claims)
                {
                    var result = await UserManager.RemoveClaimAsync(user, claim);
                    if (!result.Succeeded)
                    {
                        return new IdentityManagerResult(result.Errors.First().Description);
                    }
                }
                if (!string.IsNullOrWhiteSpace(value))
                {
                    var result = await UserManager.AddClaimAsync(user, new Claim(type, value));
                    if (!result.Succeeded)
                    {
                        return new IdentityManagerResult(result.Errors.First().Description);
                    }
                }
                return IdentityManagerResult.Success;
            };
        }

        public virtual async Task<IdentityManagerResult> SetPassword(TUser user, string password)
        {
            var token = await UserManager.GeneratePasswordResetTokenAsync(user);
            var result = await UserManager.ResetPasswordAsync(user, token, password);

            if (!result.Succeeded) return new IdentityManagerResult(result.Errors.First().Description);
            return IdentityManagerResult.Success;
        }

        public virtual async Task<IdentityManagerResult> SetUsername(TUser user, string username)
        {
            var result = await UserManager.SetUserNameAsync(user, username);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            return IdentityManagerResult.Success;
        }

        public virtual Task<string> GetEmail(TUser user) => UserManager.GetEmailAsync(user);
        public virtual async Task<IdentityManagerResult> SetEmail(TUser user, string email)
        {
            var result = await UserManager.SetEmailAsync(user, email);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            if (!string.IsNullOrWhiteSpace(email))
            {
                var token = await UserManager.GenerateEmailConfirmationTokenAsync(user);
                result = await UserManager.ConfirmEmailAsync(user, token); // TODO: check internal usage of reset/confirmation tokens is still valid
                if (!result.Succeeded) return new IdentityManagerResult(result.Errors.First().Description);
            }

            return IdentityManagerResult.Success;
        }

        public virtual Task<string> GetPhone(TUser user) => UserManager.GetPhoneNumberAsync(user);
        public virtual async Task<IdentityManagerResult> SetPhone(TUser user, string phone)
        {
            var result = await UserManager.SetPhoneNumberAsync(user, phone);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            if (!string.IsNullOrWhiteSpace(phone))
            {
                var token = await UserManager.GenerateChangePhoneNumberTokenAsync(user, phone);
                result = await UserManager.ChangePhoneNumberAsync(user, phone, token);
                if (!result.Succeeded)
                {
                    return new IdentityManagerResult(result.Errors.First().Description);
                }
            }

            return IdentityManagerResult.Success;
        }

        public virtual Task<bool> GetTwoFactorEnabled(TUser user) => UserManager.GetTwoFactorEnabledAsync(user);
        public virtual async Task<IdentityManagerResult> SetTwoFactorEnabled(TUser user, bool enabled)
        {
            var result = await UserManager.SetTwoFactorEnabledAsync(user, enabled);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            return IdentityManagerResult.Success;
        }

        public virtual Task<bool> GetLockoutEnabled(TUser user) => UserManager.GetLockoutEnabledAsync(user);
        public virtual async Task<IdentityManagerResult> SetLockoutEnabled(TUser user, bool enabled)
        {
            var result = await UserManager.SetLockoutEnabledAsync(user, enabled);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            return IdentityManagerResult.Success;
        }

        public virtual Task<bool> GetLockedOut(TUser user) => UserManager.IsLockedOutAsync(user);
        public virtual async Task<IdentityManagerResult> SetLockedOut(TUser user, bool locked)
        {
            if (locked)
            {
                var result = await UserManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
                if (!result.Succeeded)
                {
                    return new IdentityManagerResult(result.Errors.First().Description);
                }
            }
            else
            {
                var result = await UserManager.SetLockoutEndDateAsync(user, DateTimeOffset.MinValue);
                if (!result.Succeeded)
                {
                    return new IdentityManagerResult(result.Errors.First().Description);
                }
            }

            return IdentityManagerResult.Success;
        }

        public virtual async Task<IdentityManagerResult> SetName(TRole user, string name)
        {
            var result = await RoleManager.SetRoleNameAsync(user, name);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First().Description);
            }

            return IdentityManagerResult.Success;
        }

        protected virtual Task<string> GetUserProperty(PropertyMetadata propMetadata, TUser user)
        {
            if (propMetadata.TryGet(user, out var val)) return val;
            throw new Exception("Invalid property type " + propMetadata.Type);
        }

        protected virtual Task<IdentityManagerResult> SetUserProperty(IEnumerable<PropertyMetadata> propsMeta, TUser user, string type, string value)
        {
            if (propsMeta.TrySet(user, type, value, out var result)) return result;
            throw new Exception("Invalid property type " + type);
        }

        protected virtual async Task<string> DisplayNameFromUser(TUser user)
        {
            if (UserManager.SupportsUserClaim)
            {
                var claims = await UserManager.GetClaimsAsync(user);
                var name = claims.Where(x => x.Type == Constants.ClaimTypes.Name).Select(x => x.Value).FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(name)) return name;
            }

            return null;
        }

        protected virtual IEnumerable<string> ValidateUserProperty(string type, string value)
        {
            return Enumerable.Empty<string>();
        }

        protected virtual void ValidateSupportsRoles()
        {
            if (RoleManager == null) throw new InvalidOperationException("Roles Not Supported");
        }

        protected virtual Task<string> GetRoleProperty(PropertyMetadata propMetadata, TRole role)
        {
            if (propMetadata.TryGet(role, out var val)) return val;
            throw new Exception("Invalid property type " + propMetadata.Type);
        }

        protected virtual IEnumerable<string> ValidateRoleProperty(string type, string value)
        {
            return Enumerable.Empty<string>();
        }

        protected virtual Task<IdentityManagerResult> SetRoleProperty(IEnumerable<PropertyMetadata> propsMeta, TRole role, string type, string value)
        {
            if (propsMeta.TrySet(role, type, value, out var result)) return result;
            throw new Exception("Invalid property type " + type);
        }
    }
}