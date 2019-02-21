# NetCoreWinAuth

An example ASP.NET Core application that uses Windows authentication and custom authorization policies based on Windows group membership.

The project consists of a single API controller, with 3 routes:

* `/` - returns the user name of the calling user.
* `/groups` - returns the names of all of the Windows groups that the calling user is a member of.
* `/restricted` - returns a message if the calling user is a member of a group that meets the authorization policy requirements (see below).

## Getting Started

`AuthorizationPolicies.cs` is used to define the authorization policies for the application. Modify the `AuthorizationPolicies.ConfigurePolicies` method to specify the group(s) that are allowed to access the `/restricted` route.
