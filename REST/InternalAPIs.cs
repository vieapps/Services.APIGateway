#region Related components
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Web;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.V2;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class InternalAPIs
	{
		static Dictionary<string, IService> Services = new Dictionary<string, IService>();

		internal static async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare request information
			var requestInfo = new RequestInfo()
			{
				Session = Global.GetSession(context.Request.Headers, context.Request.QueryString, context.Request.UserHostAddress, context.Request.UserAgent, context.Request.UrlReferrer),
				Verb = context.Request.HttpMethod,
				ServiceName = context.Request.QueryString["service-name"],
				ObjectName = context.Request.QueryString["object-name"],
				Query = context.Request.QueryString.ToDictionary(),
				Header = context.Request.Headers.ToDictionary()
			};

			if (string.IsNullOrWhiteSpace(requestInfo.ServiceName))
				requestInfo.ServiceName = "unknown";

			if (string.IsNullOrWhiteSpace(requestInfo.ObjectName))
				requestInfo.ObjectName = "unknown";

			// check authenticate (JSON Web Token)
			var appToken = requestInfo.GetParameter("x-app-token");
			var isAuthorizeRequired = requestInfo.ServiceName.IsEquals("users") && requestInfo.ObjectName.IsEquals("session") && requestInfo .Verb.IsEquals("GET")
				? false
				: true;

			// stop if not authenticated
			if (isAuthorizeRequired && string.IsNullOrWhiteSpace(appToken))
			{
				Global.ShowError(context, new InvalidSessionException("Session is invalid (JSON Web Token is not found)"));
				return;
			}

			// check authorized with access token
			if (!string.IsNullOrWhiteSpace(appToken))
				try
				{
					var info = await Global.ParseJSONWebTokenAsync(appToken);
					requestInfo.Session.SessionID = info.Item1;
					requestInfo.Session.User = info.Item2;
				}
				catch (Exception ex)
				{
					Global.ShowError(context, ex);
					return;
				}

			// prepare body of the request
			if (requestInfo.Verb.IsEquals("POST") || requestInfo.Verb.IsEquals("PUT"))
				using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
				{
					requestInfo.Body = await reader.ReadToEndAsync();
				}

			// read from the query-string
			else if (requestInfo.Verb.IsEquals("GET"))
			{
				requestInfo.Body = context.Request.QueryString["request-body"];
				if (!string.IsNullOrWhiteSpace(requestInfo.Body))
					try
					{
						requestInfo.Body = requestInfo.Body.Url64Decode();
					}
					catch
					{
						requestInfo.Body = "";
					}
			}

			// assign identities
			if (string.IsNullOrWhiteSpace(requestInfo.Session.SessionID))
				requestInfo.Session.SessionID = UtilityService.GetUUID();
			requestInfo.Session.CorrelationID = Global.GetCorrelationID(context.Items);

			// call the API
			try
			{
				// prepare
				var key = requestInfo.ServiceName.Trim().ToLower();
				if (!InternalAPIs.Services.TryGetValue(key, out IService service))
				{
					await Global.OpenOutgoingChannelAsync();
					lock (InternalAPIs.Services)
					{
						if (!InternalAPIs.Services.TryGetValue(key, out service))
						{
							service = Global.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IService>(new CachedCalleeProxyInterceptor(new ProxyInterceptor(key)));
							InternalAPIs.Services.Add(key, service);
						}
					}
				}

				// call
				var json = await service.ProcessRequestAsync(requestInfo);

				// normalize and write down
				json = new JObject()
				{
					{ "Status", "OK" },
					{ "Data", json }
				};

				context.Response.ContentType = "application/json";
				await context.Response.Output.WriteAsync(json.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));
			}
			catch (Exception ex)
			{
				Global.ShowError(context, ex);
			}
		}
	}
}