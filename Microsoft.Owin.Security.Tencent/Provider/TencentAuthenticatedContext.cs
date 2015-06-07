using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Tencent.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class TencentAuthenticatedContext:BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="TencentAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Tencent Access token</param>
        public TencentAuthenticatedContext(IOwinContext context, JObject user, string accessToken, int expiresIn)
            : base(context)
        {
            AccessToken = accessToken;
            User = user;
			ExpiresIn = TimeSpan.FromSeconds(expiresIn);
            Id = TryGetValue(user, "openid");
			Name = TryGetValue(user, "displayName");
			Email = TryGetValue(user, "emailAddress");
			Alias = TryGetValue(user, "publicAlias");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Tencent user obtained from the endpoint https://graph.qq.com/oauth2.0/me
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Tencent OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Tencent access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Get the user's id
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Get the user's displayName
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Get the user's email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Get the user's publicAlias
        /// </summary>
        public string Alias { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
