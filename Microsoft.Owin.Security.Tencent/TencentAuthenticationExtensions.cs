using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Owin;


namespace Microsoft.Owin.Security.Tencent
{
    public static class TencentAuthenticationExtensions
    {
        public static IAppBuilder UseTencentAuthentication(this IAppBuilder app, TencentAuthenticationOptions options)
        {
            if (app == null) throw new ArgumentNullException("app");
            if (options == null) throw new ArgumentNullException("options");

            app.Use(typeof(TencentAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseTencentAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            return app.UseTencentAuthentication(new TencentAuthenticationOptions
            {
                AppId = appId,
                AppSecret = appSecret,
                Schema="https"
            });
        }
    }
}
