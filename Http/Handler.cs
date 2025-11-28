#region Related components
using System;
using System.Net;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class Handler
	{
		string LoadBalancerHealthCheckURL => UtilityService.GetAppSetting("LoadBalancer:HealthCheckURL", "/load-balancer-health-check");

		public Handler(RequestDelegate _) { }

		public Task Invoke(HttpContext context)
		{
			// request of WebSocket
			if (context.WebSockets.IsWebSocketRequest)
				return Task.WhenAll
				(
					Global.IsVisitLogEnabled ? context.WriteLogsAsync(Global.Logger, "Http.Visits", $"Wrap a WebSocket connection successful\r\n- Endpoint: {context.GetRemoteIPAddress()}:{context.Connection.RemotePort}\r\n- URI: {context.GetRequestUri()}{(Global.IsDebugLogEnabled ? $"\r\n- Headers:\r\n\t{context.Request.Headers.Select(kvp => $"{kvp.Key}: {kvp.Value}").Join("\r\n\t")}" : "")}") : Task.CompletedTask,
					APIGateway.WebSocketAPIs.WebSocket.WrapAsync(context)
				);

			// CORS: allow origin
			context.Response.Headers.AccessControlAllowOrigin = "*";

			// CORS: options
			if (context.Request.Method.IsEquals("OPTIONS"))
			{
				var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					["X-Node"] = Global.NodeID,
					["Access-Control-Allow-Methods"] = "HEAD,GET,POST,PUT,PATCH,DELETE"
				};
				if (context.Request.Headers.TryGetValue("Access-Control-Request-Headers", out var requestHeaders))
					headers["Access-Control-Allow-Headers"] = requestHeaders;
				context.SetResponseHeaders((int)HttpStatusCode.OK, headers);
				return Task.CompletedTask;
			}

			// health check
			if (context.Request.Path.Value.IsEquals(this.LoadBalancerHealthCheckURL))
				return context.WriteAsync("OK", "text/plain", null, 0, null, TimeSpan.Zero, null, Global.CancellationToken);

			// requests of the service
			return this.ProcessRequestAsync(context);
		}

		async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare
			context.SetItem("PipelineStopwatch", Stopwatch.StartNew());
			context.SetItem("Correlation-ID", context.GetParameter("x-original-correlation-id") ?? context.GetParameter("x-correlation-id") ?? UtilityService.NewUUID);

			if (Global.IsVisitLogEnabled)
				await context.WriteVisitStartingLogAsync().ConfigureAwait(false);

			var requestPath = context.GetRequestPathSegments(true).First();

			// request to favicon.ico file
			if (requestPath.Equals("favicon.ico"))
				await context.ProcessFavouritesIconFileRequestAsync().ConfigureAwait(false);

			// request to robots.txt file
			else if (requestPath.Equals("robots.txt"))
				await context.WriteAsync("User-agent: *\r\nDisallow: *", "text/plain", null, 0, "public", TimeSpan.Zero, null, Global.CancellationToken).ConfigureAwait(false);

			// request to static segments
			else if (Global.StaticSegments.Contains(requestPath))
				await context.ProcessStaticFileRequestAsync().ConfigureAwait(false);

			// request to services
			else
				await APIGateway.RESTfulAPIs.ProcessRequestAsync(context).ConfigureAwait(false);

			if (Global.IsVisitLogEnabled)
				await context.WriteVisitFinishingLogAsync().ConfigureAwait(false);
		}

		public class RESTfulAPIs { }

		public class WebSocketAPIs { }

	}
}