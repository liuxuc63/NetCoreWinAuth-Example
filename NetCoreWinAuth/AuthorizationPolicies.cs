using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace NetCoreWinAuth {
    internal static class AuthorizationPolicies {

        /// <summary>
        /// This is the name of the custom authorization policy we will add. We can reference this 
        /// policy name in the [Authorize] attributes we add to controllers and controller actions.
        /// </summary>
        internal const string MustBeAMemberOfMyAppUsersGroup = "RestrictAccessToAuthorizedGroups";


        internal static void ConfigurePolicies(AuthorizationOptions options) {
            options.AddPolicy(MustBeAMemberOfMyAppUsersGroup, policy => {
                // Define the names of the allowed groups here. You could hard code them or e.g. 
                // load them in from a configuration file.
                var allowedRoles = new string[] {
                    // @"SOME_DOMAIN\someDomainGroup",
                    // @"SOME_MACHINE_NAME\someLocalGroup"
                };

                // All ClaimsIdentity objects define a RoleClaimType object that tells .NET which 
                // claims on the identity correspond to role memberships. On WindowsIdentity objects 
                // (which derive from ClaimsIdentity), a role claim is added for each group that the 
                // user is a member of. The value of each role claim is the Windows security 
                // identifier (SID) for the group.
                // 
                // The GetSidForIdentityName method allows us to easily find a Windows group by name 
                // and get the SID for the group.
                policy.RequireRole(allowedRoles.Select(x => GetSidForIdentityName(x)));
            });
        }


        /// <summary>
        /// Get the security identifier (SID) for a user or group name.
        /// </summary>
        /// <param name="userOrGroupName"></param>
        /// <returns></returns>
        internal static string GetSidForIdentityName(string userOrGroupName) {
            var account = new NTAccount(userOrGroupName);
            var sid = (SecurityIdentifier) account.Translate(typeof(SecurityIdentifier));
            return sid.Value;
        }


        /// <summary>
        /// Get the user or group name for a security identifier (SID).
        /// </summary>
        /// <param name="securityIdentifier"></param>
        /// <returns></returns>
        internal static string GetIdentityNameForSid(string securityIdentifier) {
            var sid = new SecurityIdentifier(securityIdentifier);
            var account = (NTAccount) sid.Translate(typeof(NTAccount));
            return account.Value;
        }

    }
}
