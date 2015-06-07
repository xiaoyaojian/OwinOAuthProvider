using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Tencent.Provider
{
    /// <summary>
    /// Default <see cref="ITencentAuthenticationProvider"/> implementation.
    /// </summary>
    public class TencentAuthenticationProvider:ITencentAuthenticationProvider
    {
        // <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<TencentAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<TencentReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Initializes a <see cref="TencentAuthenticationProvider"/>
        /// </summary>
        public TencentAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Invoked whenever tencent succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public Task Authenticated(TencentAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public Task ReturnEndpoint(TencentReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
