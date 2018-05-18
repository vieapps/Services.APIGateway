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
		readonly RequestDelegate _next;
		readonly IHostingEnvironment _environment;

		public Handler(RequestDelegate next, IHostingEnvironment environment)
		{
			this._next = next;
			this._environment = environment;
		}

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
				await this._next.Invoke(context).ConfigureAwait(false);
			}
			catch (InvalidOperationException) { }
			catch (Exception ex)
			{
				Global.Logger.LogError($"Error occurred while invoking the next middleware: {ex.Message}", ex);
			}
		}

		internal async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare
			context.Items["PipelineStopwatch"] = Stopwatch.StartNew();
			var requestPath = context.GetRequestPathSegments().First().ToLower();

			// request to favicon.ico file
			if (requestPath.IsEquals("favicon.ico"))
				context.ShowHttpError((int)HttpStatusCode.NotFound, "Not Found", "FileNotFoundException", context.GetCorrelationID());

			// request to static segments
			else if (Global.StaticSegments.Count > 0 && Global.StaticSegments.Contains(requestPath))
				await this.ProcessStaticRequestAsync(context).ConfigureAwait(false);

			// request to external APIs
			else if (APIGateway.ExternalAPIs.APIs.ContainsKey(requestPath))
				await APIGateway.ExternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);

			// request to internal APIs
			else
				await APIGateway.InternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);
		}

		internal async Task ProcessStaticRequestAsync(HttpContext context)
		{
			try
			{
				// prepare
				FileInfo fileInfo = null;
				var pathSegments = context.GetRequestPathSegments();
				var filePath = pathSegments[0].IsEquals("statics")
					? UtilityService.GetAppSetting("Path:StaticFiles", this._environment.ContentRootPath + "/data-files/statics")
					: this._environment.ContentRootPath;
				filePath += ("/" + string.Join("/", pathSegments)).Replace("/statics/", "/").Replace("//", "/").Replace(@"\", "/").Replace("/", Path.DirectorySeparatorChar.ToString());

				// check request headers to reduce traffict
				var requestUri = context.GetRequestUri();
				var eTag = "Static#" + $"{requestUri}".ToLower().GenerateUUID();
				if (eTag.IsEquals(context.Request.Headers["If-None-Match"].First()))
				{
					var isNotModified = true;
					var lastModifed = DateTime.Now;

					// last-modified
					if (!context.Request.Headers["If-Modified-Since"].First().Equals(""))
					{
						fileInfo = new FileInfo(filePath);
						if (fileInfo.Exists)
						{
							lastModifed = fileInfo.LastWriteTime;
							isNotModified = lastModifed <= context.Request.Headers["If-Modified-Since"].First().FromHttpDateTime();
						}
						else
							isNotModified = false;
					}

					// update header and stop
					if (isNotModified)
					{
						context.SetResponseHeaders((int)HttpStatusCode.NotModified, eTag, lastModifed.ToUnixTimestamp(), "public", context.GetCorrelationID());
						if (Global.IsDebugLogEnabled)
							context.WriteLogs("StaticFiles", $"Response to request with status code 304 to reduce traffic ({filePath})");
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
				await context.WriteAsync(fileContent.ToArraySegment(), Global.CancellationTokenSource.Token).ConfigureAwait(false);
				if (Global.IsDebugLogEnabled)
					context.WriteLogs("StaticFiles", $"Response to request successful ({filePath} - {fileInfo.Length:#,##0} bytes)");
			}
			catch (Exception ex)
			{
				context.WriteLogs("StaticFiles", $"Error occurred while processing [{context.GetRequestUri()}]", ex);
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