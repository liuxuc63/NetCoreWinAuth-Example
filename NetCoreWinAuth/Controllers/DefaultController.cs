using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace NetCoreWinAuth.Controllers {
    [Route("")]
    [ApiController]
    [Authorize]
    public class DefaultController : ControllerBase {

        [HttpGet]
        [Route("")]
        [ProducesResponseType(typeof(string), 200)]
        public IActionResult GetUserName() {
            return Ok(User.Identity.Name); // 200
        }


        [HttpGet]
        [Route("groups")]
        [ProducesResponseType(typeof(IDictionary<string, string[]>), 200)]
        public IActionResult GetGroups() {
            var groups = User
                .Identities
                .SelectMany(identity => identity.FindAll(x => identity.RoleClaimType.Equals(x.Type)).Select(x => new { x.Issuer, x.Value }))
                .ToLookup(x => x.Issuer)
                .ToDictionary(x => x.Key, x => x.Select(g => AuthorizationPolicies.GetIdentityNameForSid(g.Value)).ToArray());
            return Ok(groups); // 200
        }


        [HttpGet]
        [Route("restricted")]
        // Restrict access to callers who satisfy our custom authorization policy.
        [Authorize(Policy = AuthorizationPolicies.MustBeAMemberOfMyAppUsersGroup)]
        [ProducesResponseType(typeof(string), 200)]
        public IActionResult RestrictedRoute() {
            return Ok("You are authorized!"); // 200
        }

    }
}