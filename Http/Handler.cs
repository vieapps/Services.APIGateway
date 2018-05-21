#region Related components
using System;
using System.Net;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;

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
				await APIGateway.RTU.WebSocket.WrapAsync(context).ConfigureAwait(false);

			// request of HTTP
			else
			{
				// allow origin
				context.Response.Headers["Access-Control-Allow-Origin"] = "*";

				// request with OPTIONS verb
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

				// request with other verbs
				else
					await this.ProcessRequestAsync(context).ConfigureAwait(false);
			}

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

		internal async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare
			context.Items["PipelineStopwatch"] = Stopwatch.StartNew();
			var path = context.GetRequestPathSegments(true).First();

			// request to favicon.ico file
			if (path.Equals("favicon.ico"))
				context.ShowHttpError((int)HttpStatusCode.NotFound, "Not Found", "FileNotFoundException", context.GetCorrelationID());

			// request to static segments
			else if (Global.StaticSegments.Contains(path))
				await this.ProcessStaticRequestAsync(context).ConfigureAwait(false);

			// request to external APIs
			else if (APIGateway.ExternalAPIs.APIs.ContainsKey(path))
				await APIGateway.ExternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);

			// request to internal APIs
			else
				await APIGateway.InternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);
		}

		internal async Task ProcessStaticRequestAsync(HttpContext context)
		{
			var requestUri = context.GetRequestUri();
			try
			{
				// prepare
				FileInfo fileInfo = null;
				var pathSegments = requestUri.GetRequestPathSegments();
				var filePath = pathSegments[0].IsEquals("statics")
					? UtilityService.GetAppSetting("Path:StaticFiles", Global.RootPath + "/data-files/statics")
					: Global.RootPath;
				filePath += ("/" + string.Join("/", pathSegments)).Replace("/statics/", "/").Replace("//", "/").Replace(@"\", "/").Replace("/", Path.DirectorySeparatorChar.ToString());

				// check request headers to reduce traffict
				var eTag = "Static#" + $"{requestUri}".ToLower().GenerateUUID();
				if (eTag.IsEquals(context.GetHeaderParameter("If-None-Match")))
				{
					var isNotModified = true;
					var lastModifed = DateTime.Now.ToUnixTimestamp();
					if (context.GetHeaderParameter("If-Modified-Since") != null)
					{
						fileInfo = new FileInfo(filePath);
						if (fileInfo.Exists)
						{
							lastModifed = fileInfo.LastWriteTime.ToUnixTimestamp();
							isNotModified = lastModifed <= context.GetHeaderParameter("If-Modified-Since").FromHttpDateTime().ToUnixTimestamp();
						}
						else
							isNotModified = false;
					}
					if (isNotModified)
					{
						context.SetResponseHeaders((int)HttpStatusCode.NotModified, eTag, lastModifed, "public", context.GetCorrelationID());
						if (Global.IsDebugLogEnabled)
							await context.WriteLogsAsync("StaticFiles", $"Response with status code 304 to reduce traffic ({filePath})").ConfigureAwait(false);
						return;
					}
				}

				// check existed
				fileInfo = fileInfo ?? new FileInfo(filePath);
				if (!fileInfo.Exists)
					throw new FileNotFoundException($"Not Found [{requestUri}]");

				// prepare body
				var fileMimeType = fileInfo.GetMimeType();
				var fileContent = fileMimeType.IsEndsWith("json")
					? JObject.Parse(await UtilityService.ReadTextFileAsync(fileInfo, null, Global.CancellationTokenSource.Token).ConfigureAwait(false)).ToString(Formatting.Indented).ToBytes()
					: await UtilityService.ReadBinaryFileAsync(fileInfo, Global.CancellationTokenSource.Token).ConfigureAwait(false);

				// response
				context.SetResponseHeaders((int)HttpStatusCode.OK, new Dictionary<string, string>
				{
					{ "Content-Type", $"{fileMimeType}; charset=utf-8" },
					{ "ETag", eTag },
					{ "Last-Modified", $"{fileInfo.LastWriteTime.ToHttpString()}" },
					{ "Cache-Control", "public" },
					{ "Expires", $"{DateTime.Now.AddDays(7).ToHttpString()}" },
					{ "X-CorrelationID", context.GetCorrelationID() }
				});
				await Task.WhenAll(
					context.WriteAsync(fileContent, Global.CancellationTokenSource.Token),
					!Global.IsDebugLogEnabled ? Task.CompletedTask : context.WriteLogsAsync("StaticFiles", $"Success response ({filePath} - {fileInfo.Length:#,##0} bytes)")
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WriteLogsAsync("StaticFiles", $"Failure response [{requestUri}]", ex).ConfigureAwait(false);
				context.ShowHttpError(ex.GetHttpStatusCode(), ex.Message, ex.GetType().GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
			}
		}

		#region classes for logging
		public class RTU { }
		public class InternalAPIs { }
		public class ExternalAPIs { }
		#endregion

	}
}