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
		string LoadBalancerHealthCheckURL { get; } = UtilityService.GetAppSetting("LoadBalancer:HealthCheckURL", "/load-balancer-health-check");

		public Handler(RequestDelegate _) { }

		public async Task Invoke(HttpContext context)
		{
			if (!context.Request.Method.IsEquals("OPTIONS"))
			{
				// Web Socket
				if (context.WebSockets.IsWebSocketRequest)
					await Task.WhenAll
					(
						Global.IsVisitLogEnabled ? context.WriteLogsAsync(Global.Logger, "WebSocketAPIs", $"Wrap a WebSocket connection successful\r\n- Endpoint: {context.GetRemoteIPAddress()}:{context.Connection.RemotePort}\r\n- URI: {context.GetRequestUri()}{(Global.IsDebugLogEnabled ? $"\r\n- Headers:\r\n\t{context.Request.Headers.Select(kvp => $"{kvp.Key}: {kvp.Value}").Join("\r\n\t")}" : "")}") : Task.CompletedTask,
						APIGateway.WebSocketAPIs.WrapWebSocketAsync(context)
					).ConfigureAwait(false);

				// Event Stream (Server Sent Event)
				else if (context.IsEventStreamRequest())
					await Task.WhenAll
					(
						Global.IsVisitLogEnabled ? context.WriteLogsAsync(Global.Logger, "WebSocketAPIs", $"Wrap an EventStream connection successful\r\n- Endpoint: {context.GetRemoteIPAddress()}:{context.Connection.RemotePort}\r\n- URI: {context.GetRequestUri()}{(Global.IsDebugLogEnabled ? $"\r\n- Headers:\r\n\t{context.Request.Headers.Select(kvp => $"{kvp.Key}: {kvp.Value}").Join("\r\n\t")}" : "")}") : Task.CompletedTask,
						APIGateway.WebSocketAPIs.WrapEventStreamAsync(context)
					).ConfigureAwait(false);

				// HTTP
				else
				{
					await (context.Request.Path.Value.IsEquals(this.LoadBalancerHealthCheckURL) ? context.WriteAsync("OK", "text/plain", null, 0, null, TimeSpan.Zero, null, Global.CancellationToken) : this.ProcessRequestAsync(context)).ConfigureAwait(false);
					if (Global.IsVisitLogEnabled)
						await context.WriteVisitFinishingLogAsync().ConfigureAwait(false);
				}
			}
		}

		async Task ProcessRequestAsync(HttpContext context)
		{
			RouterRpcGate.Releaser? ticket = null;
			var stopwatch = Stopwatch.StartNew();
			try
			{
				var requestPath = context.GetRequestPathSegments(true).First();

				if (requestPath.Equals("favicon.ico"))
					await context.ProcessFavouritesIconFileRequestAsync().ConfigureAwait(false);

				else if (requestPath.Equals("robots.txt"))
					await context.WriteAsync("User-agent: *\r\nDisallow: *", "text/plain", null, 0, "public", TimeSpan.Zero, null, context.RequestAborted).ConfigureAwait(false);

				else if (Global.StaticSegments.Contains(requestPath))
					await context.ProcessStaticFileRequestAsync().ConfigureAwait(false);

				else
				{
					ticket = await Global.RpcGate.TryEnterAsync(context.RequestAborted).ConfigureAwait(false);
					if (ticket == null)
					{
						Global.Statistics.RpcRejected();
						throw new SystemBusyException();
					}
					Global.Statistics.RpcEntered();
					using (ticket.Value)
					{
						await APIGateway.RESTfulAPIs.ProcessRequestAsync(context).ConfigureAwait(false);
					}
				}
			}
			catch (Exception ex)
			{
				context.WriteError(APIGateway.RESTfulAPIs.Logger, ex);
			}
			finally
			{
				if (ticket != null)
					Global.Statistics.RpcCompleted(stopwatch);
			}
		}

		public class RESTfulAPIs { }

		public class WebSocketAPIs { }

	}

	public class Starter(RequestDelegate next)
	{
		readonly RequestDelegate NextAsync = next;

		public async Task Invoke(HttpContext context)
		{
			// process the request of HTTP
			if (!context.WebSockets.IsWebSocketRequest && !context.IsEventStreamRequest())
			{
				// CORS options
				context.Response.Headers.AccessControlAllowOrigin = "*";
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
				}

				// visit logs
				else
				{
					context.SetItem("PipelineStopwatch", Stopwatch.StartNew());
					if (Global.IsVisitLogEnabled)
						await context.WriteVisitStartingLogAsync().ConfigureAwait(false);
				}
			}

			// next step
			await this.NextAsync(context).ConfigureAwait(false);
		}
	}
}