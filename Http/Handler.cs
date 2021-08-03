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
		string LoadBalancingHealthCheckUrl { get; } = UtilityService.GetAppSetting("HealthCheckUrl", "/load-balancing-health-check");

		public Handler(RequestDelegate _) { }

		public async Task Invoke(HttpContext context)
		{
			// request of WebSocket
			if (context.WebSockets.IsWebSocketRequest)
				await Task.WhenAll
				(
					Global.IsVisitLogEnabled ? context.WriteLogsAsync(Global.Logger, "Http.Visits", $"Wrap a WebSocket connection successful\r\n- Endpoint: {context.Connection.RemoteIpAddress}:{context.Connection.RemotePort}\r\n- URI: {context.GetRequestUri()}{(Global.IsDebugLogEnabled ? $"\r\n- Headers:\r\n\t{context.Request.Headers.Select(kvp => $"{kvp.Key}: {kvp.Value}").Join("\r\n\t")}" : "")}") : Task.CompletedTask,
					APIGateway.WebSocketAPIs.WrapWebSocketAsync(context)
				).ConfigureAwait(false);

			// request of HTTP
			else
			{
				// CORS policy => allow origin
				context.Response.Headers["Access-Control-Allow-Origin"] = "*";

				// CORS options
				if (context.Request.Method.IsEquals("OPTIONS"))
				{
					var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						["Access-Control-Allow-Methods"] = "HEAD,GET,POST,PUT,PATCH,DELETE"
					};
					if (context.Request.Headers.TryGetValue("Access-Control-Request-Headers", out var requestHeaders))
						headers["Access-Control-Allow-Headers"] = requestHeaders;
					context.SetResponseHeaders((int)HttpStatusCode.OK, headers);
					await context.FlushAsync(Global.CancellationToken).ConfigureAwait(false);
				}

				// load balancing health check
				else if (context.Request.Path.Value.IsEquals(this.LoadBalancingHealthCheckUrl))
					await context.WriteAsync("OK", "text/plain", null, 0, null, TimeSpan.Zero, null, Global.CancellationToken).ConfigureAwait(false);

				// APIs
				else
					await this.ProcessRequestAsync(context).ConfigureAwait(false);
			}
		}

		async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare
			context.SetItem("PipelineStopwatch", Stopwatch.StartNew());
			var requestPath = context.GetRequestPathSegments(true).First();

			if (Global.IsVisitLogEnabled)
				await context.WriteVisitStartingLogAsync().ConfigureAwait(false);

			// request to favicon.ico file
			if (requestPath.Equals("favicon.ico"))
				await context.ProcessFavouritesIconFileRequestAsync().ConfigureAwait(false);

			// request to robots.txt file
			else if (requestPath.Equals("robots.txt"))
				context.WriteError((int)HttpStatusCode.NotFound, "Not Found", "FileNotFoundException", context.GetCorrelationID());

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