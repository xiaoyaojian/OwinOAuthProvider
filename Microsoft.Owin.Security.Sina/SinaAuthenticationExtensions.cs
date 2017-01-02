using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Sina
{
    public static class SinaAuthenticationExtensions
    {
        public static IAppBuilder UseSinaAuthentication(this IAppBuilder app, SinaAuthenticationOptions options)
        { 
            if (app == null) throw new ArgumentNullException("app");
            if (options == null) throw new ArgumentNullException("options");

            app.Use(typeof(SinaAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseSinaAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            return app.UseSinaAuthentication(new SinaAuthenticationOptions
            {
                AppId = appId,
                AppSecret = appSecret,
                Schema = "https"
            });
        }
    }
}
