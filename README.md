#Sina and Tencent open authentication provider of OWIN#
##Installation##
Use following command to install each package in your project
`Install-Package Microsoft.Owin.Security.Sina` and
`Install-Package Microsoft.Owin.Security.Tencent`
##Getting Started##
Before you use these package,i assume you already created your own application in [connect.qq.com](http://connect.qq.com/ "Open QQ") or [open.weibo.com](https://open.weibo.com/ "Open Weibo").

1. Create an asp.net 5 web application ,and select 'MVC' template.do not change authentication setting.
2. Install these providers
3. Open `Startup.Auth.cs` file,add following namespaces
	1. `Microsoft.Owin.Security.Sina`
	2. `Microsoft.Owin.Security.Tencent`
4. add following code section with your 'appId' and 'secretId'.
	1. `app.UseSinaAuthentication("YOUR APP ID", "YOUR SECRET ID");`
	2. `app.UseTencentAuthentication("YOUR APP ID", "YOUR SECRET ID");`
5. Try to run your application with the domain address you designated in management center of each open platform
