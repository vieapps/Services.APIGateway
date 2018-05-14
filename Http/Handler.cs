#region Related components
using System;
using System.Net;
using System.IO;
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
		readonly IHostingEnvironment _hostingEnvironment;

		public Handler(RequestDelegate next, IHostingEnvironment hostingEnvironment)
		{
			this._next = next;
			this._hostingEnvironment = hostingEnvironment;
		}

		public async Task Invoke(HttpContext context)
		{
			// request of WebSocket
			if (context.WebSockets.IsWebSocketRequest)
				await RTU.WebSocket.WrapAsync(context).ConfigureAwait(false);

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
			var requestUri = context.GetRequestUri();
			var correlationID = context.GetCorrelationID();
			context.Items["PipelineStopwatch"] = Stopwatch.StartNew();

			var executionFilePath = requestUri.PathAndQuery;
			if (executionFilePath.IndexOf("?") > 0)
				executionFilePath = executionFilePath.Left(executionFilePath.IndexOf("?"));
			if (executionFilePath.Equals("~/") || executionFilePath.Equals("/"))
				executionFilePath = "";
			var executionFilePaths = string.IsNullOrWhiteSpace(executionFilePath)
				? new[] { "" }
				: executionFilePath.ToLower().ToArray('/', true);

			// request to favicon.ico file
			if (executionFilePaths[0].IsEquals("favicon.ico"))
				context.ShowHttpError((int)HttpStatusCode.NotFound, "Not Found", "FileNotFoundException", context.GetCorrelationID());

			// request to by-pass segments
			else if (Global.BypassSegments.Count > 0 && Global.BypassSegments.Contains(executionFilePaths[0]))
			{
				// do nothinng
			}

			// request to static segments
			else if (Global.StaticSegments.Count > 0 && Global.StaticSegments.Contains(executionFilePaths[0]))
				await this.ProcessStaticRequestAsync(context, executionFilePaths[0]).ConfigureAwait(false);

			// request to external APIs
			else if (ExternalAPIs.APIs.ContainsKey(executionFilePaths[0]))
				await ExternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);

			// request to internal APIs
			else
				await InternalAPIs.ProcessRequestAsync(context).ConfigureAwait(false);
		}

		internal async Task ProcessStaticRequestAsync(HttpContext context, string path)
		{
			var requestUri = context.GetRequestUri();
			try
			{
				// prepare
				var rootPath = path.IsEquals("statics")
					? UtilityService.GetAppSetting("Path:StaticFiles", this._hostingEnvironment.ContentRootPath + "/data-files/statics")
					: this._hostingEnvironment.ContentRootPath;

				var filePath = string.IsNullOrWhiteSpace(requestUri.PathAndQuery)
					? "/geo/countries.json"
					: requestUri.PathAndQuery;

				if (filePath.IndexOf("?") > 0)
					filePath = filePath.Left(filePath.IndexOf("?"));

				filePath = (rootPath + filePath.Replace("/statics/", "/")).Replace("//", "/").Replace(@"\", "/").Replace("/", Path.DirectorySeparatorChar.ToString());
				FileInfo fileInfo = null;

				// check caching headers to reduce traffic
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
						context.SetResponseHeaders((int)HttpStatusCode.NotModified, new Dictionary<string, string>
						{
							{ "Cache-Control", "public" },
							{ "ETag", eTag },
							{ "Last-Modifed", $"{lastModifed.ToHttpString()}" }
						}, true);
						if (Global.IsDebugLogEnabled)
							Global.Logger.LogDebug($"Response to request of static file with code 304 to reduce traffic ({filePath})");
						return;
					}
				}

				// check existed
				fileInfo = fileInfo ?? new FileInfo(filePath);
				if (!fileInfo.Exists)
					throw new FileNotFoundException($"Not Found [{requestUri}]");

				// prepare body
				new FileExtensionContentTypeProvider().TryGetContentType(fileInfo.Name, out string staticMimeType);
				var staticContent = await UtilityService.ReadTextFileAsync(fileInfo).ConfigureAwait(false);
				staticContent = staticMimeType.IsEndsWith("json")
					? JObject.Parse(staticContent).ToString(Formatting.Indented)
					: staticContent;

				// response
				context.SetResponseHeaders((int)HttpStatusCode.OK, new Dictionary<string, string>
				{
					{ "Content-Type", (string.IsNullOrWhiteSpace(staticMimeType) ? "text/plain" : staticMimeType) + "; charset=utf-8" },
					{ "ETag", eTag },
					{ "Last-Modified", $"{fileInfo.LastWriteTime.ToHttpString()}" },
					{ "Cache-Control", "public" },
					{ "Expires", $"{DateTime.Now.AddDays(7).ToHttpString()}" },
					{ "X-CorrelationID", context.GetCorrelationID() }
				});
				await context.WriteAsync(staticContent.ToArraySegment(), Global.CancellationTokenSource.Token).ConfigureAwait(false);
				if (Global.IsDebugLogEnabled)
					Global.Logger.LogDebug($"Response to request of static file successful ({filePath} - {fileInfo.Length:#,##0} bytes)");
			}
			catch (Exception ex)
			{
				if (!(ex is InvalidOperationException))
					Global.Logger.LogError($"Error occurred while processing request of static file [{requestUri}]", ex);
				context.ShowHttpError(ex.GetHttpStatusCode(), ex.Message, ex.GetType().GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
			}
		}
	}
}