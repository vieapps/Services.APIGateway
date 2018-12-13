#region Related components
using System;
using System.Net;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.StaticFiles;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class Handler
	{
		RequestDelegate Next { get; }

		public Handler(RequestDelegate next) => this.Next = next;

		public async Task Invoke(HttpContext context)
		{
			// request of WebSocket
			if (context.WebSockets.IsWebSocketRequest)
				await Task.WhenAll(
					Global.IsDebugLogEnabled ? context.WriteLogsAsync("RTU", $"Wrap a WebSocket connection\r\n\t{string.Join("\r\n\t", context.Request.Headers.Select(header => $"{header.Key}: {header.Value}"))}") : Task.CompletedTask,
					APIGateway.RTU.WebSocket.WrapAsync(context)
				).ConfigureAwait(false);

			// request of HTTP
			else
			{
				// CORS: allow origin
				context.Response.Headers["Access-Control-Allow-Origin"] = "*";

				// CORS: options
				if (context.Request.Method.IsEquals("OPTIONS"))
				{
					var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Access-Control-Allow-Methods", "GET,POST,PUT,DELETE" }
					};
					if (context.Request.Headers.ContainsKey("Access-Control-Request-Headers"))
						headers["Access-Control-Allow-Headers"] = context.Request.Headers["Access-Control-Request-Headers"];
					context.SetResponseHeaders((int)HttpStatusCode.OK, headers, true);
				}

				// load balancing health check
				else if (context.Request.Path.Value.IsEquals("/load-balancing-health-check"))
					await context.WriteAsync("OK", "text/plain", null, 0, null, TimeSpan.Zero, null, Global.CancellationTokenSource.Token).ConfigureAwait(false);

				// request of APIs
				else
				{
					// process
					await this.ProcessRequestAsync(context).ConfigureAwait(false);

					// invoke next middleware
					try
					{
						await this.Next.Invoke(context).ConfigureAwait(false);
					}
					catch (InvalidOperationException) { }
					catch (Exception ex)
					{
						Global.Logger.LogCritical($"Error occurred while invoking the next middleware: {ex.Message}", ex);
					}
				}
			}
		}

		internal async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare
			context.Items["PipelineStopwatch"] = Stopwatch.StartNew();
			var requestUri = context.GetRequestUri();
			var requestPath = requestUri.GetRequestPathSegments(true).First();

			// request to favicon.ico file
			if (requestPath.Equals("favicon.ico"))
			{
				context.ShowHttpError((int)HttpStatusCode.NotFound, "Not Found", "FileNotFoundException", context.GetCorrelationID());
				return;
			}

			if (Global.IsVisitLogEnabled)
				await context.WriteLogsAsync(Global.Logger, "Visits", $"Request starting {context.Request.Method} => {requestUri} (IP: {context.Connection.RemoteIpAddress} - Agent: {context.Request.Headers["User-Agent"]}{(string.IsNullOrWhiteSpace(context.Request.Headers["Referrer"]) ? "" : $" - Origin: {context.Request.Headers["Origin"]}")}{(string.IsNullOrWhiteSpace(context.Request.Headers["Referrer"]) ? "" : $" - Refer: {context.Request.Headers["Referrer"]}")})").ConfigureAwait(false);

			// request to static segments
			if (Global.StaticSegments.Contains(requestPath))
				await context.ProcessStaticFileRequestAsync().ConfigureAwait(false);

			// request to external APIs
			else if (APIGateway.ExternalAPIs.APIs.ContainsKey(requestPath))
				await APIGateway.ExternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);

			// request to internal APIs
			else
				await APIGateway.InternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);

			if (Global.IsVisitLogEnabled)
				await context.WriteLogsAsync(Global.Logger, "Visits", $"Request finished in {context.GetExecutionTimes()}").ConfigureAwait(false);
		}

		#region classes for logging
		public class RTU { }
		public class InternalAPIs { }
		public class ExternalAPIs { }
		#endregion

	}
}