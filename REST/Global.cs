#region Related components
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Linq;
using System.Web;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.Core.Listener;
using WampSharp.V2;
using WampSharp.V2.Realm;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class Global
	{
		internal static CancellationTokenSource CancellationTokenSource = new CancellationTokenSource();

		#region Get the app info
		internal static Tuple<string, string, string> GetAppInfo(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferrer)
		{
			var name = UtilityService.GetAppParameter("x-app-name", header, query, "Generic App");

			var platform = UtilityService.GetAppParameter("x-app-platform", header, query);
			if (string.IsNullOrWhiteSpace(platform))
				platform = string.IsNullOrWhiteSpace(agentString)
					? "N/A"
					: agentString.IsContains("iPhone") || agentString.IsContains("iPad") || agentString.IsContains("iPod")
						? "iOS PWA"
						: agentString.IsContains("Android")
							? "Android PWA"
							: agentString.IsContains("Windows Phone")
								? "Windows Phone PWA"
								: agentString.IsContains("BlackBerry") || agentString.IsContains("BB10")
									? "BlackBerry PWA"
									: agentString.IsContains("IEMobile") || agentString.IsContains("Opera Mini")
										? "Mobile PWA"
										: "Desktop PWA";

			var origin = header?["origin"];
			if (string.IsNullOrWhiteSpace(origin))
				origin = urlReferrer?.AbsoluteUri;
			if (string.IsNullOrWhiteSpace(origin))
				origin = ipAddress;

			return new Tuple<string, string, string>(name, platform, origin);
		}

		internal static Tuple<string, string, string> GetAppInfo(this HttpContext context)
		{
			return Global.GetAppInfo(context.Request.Headers, context.Request.QueryString, context.Request.UserAgent, context.Request.UserHostAddress, context.Request.UrlReferrer);
		}
		#endregion

		#region Encryption keys
		static string _AESKey = null;

		/// <summary>
		/// Geths the key for working with AES
		/// </summary>
		internal static string AESKey
		{
			get
			{
				if (Global._AESKey == null)
					Global._AESKey = UtilityService.GetAppSetting("AESKey", "VIEApps-c98c6942-Default-0ad9-AES-40ed-Encryption-9e53-Key-65c501fcf7b3");
				return Global._AESKey;
			}
		}

		internal static byte[] GenerateEncryptionKey(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, false, 256);
		}

		internal static byte[] GenerateEncryptionIV(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, true, 128);
		}

		static string _JWTKey = null;

		/// <summary>
		/// Geths the key for working with JSON Web Token
		/// </summary>
		internal static string JWTKey
		{
			get
			{
				if (Global._JWTKey == null)
					Global._JWTKey = UtilityService.GetAppSetting("JWTKey", "VIEApps-49d8bd8c-Default-babc-JWT-43f4-Sign-bc30-Key-355b0891dc0f");
				return Global._JWTKey;
			}
		}

		static string _PublicJWTKey = null;

		internal static string GenerateJWTKey()
		{
			if (Global._PublicJWTKey == null)
				Global._PublicJWTKey = Global.JWTKey.GetHMACSHA512(Global.AESKey).ToBase64Url(false, true);
			return Global._PublicJWTKey;
		}

		static string _RSAKey = null;

		/// <summary>
		/// Geths the key for working with RSA
		/// </summary>
		internal static string RSAKey
		{
			get
			{
				if (Global._RSAKey == null)
					Global._RSAKey = UtilityService.GetAppSetting("RSAKey", "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");
				return Global._RSAKey;
			}
		}

		static RSACryptoServiceProvider _RSA = null;

		internal static RSACryptoServiceProvider RSA
		{
			get
			{
				if (Global._RSA == null)
					try
					{
						Global._RSA = CryptoService.CreateRSAInstance(Global.RSAKey.Decrypt());
					}
					catch (Exception)
					{
						throw;
					}
				return Global._RSA;
			}
		}

		static string _RSAExponent = null;

		internal static string RSAExponent
		{
			get
			{
				if (Global._RSAExponent == null)
				{
					var xmlDoc = new System.Xml.XmlDocument();
					xmlDoc.LoadXml(Global.RSA.ToXmlString(false));
					Global._RSAExponent = xmlDoc.DocumentElement.ChildNodes[1].InnerText.ToHexa(true);
				}
				return Global._RSAExponent;
			}
		}

		static string _RSAModulus = null;

		internal static string RSAModulus
		{
			get
			{
				if (Global._RSAModulus == null)
				{
					var xmlDoc = new System.Xml.XmlDocument();
					xmlDoc.LoadXml(Global.RSA.ToXmlString(false));
					Global._RSAModulus = xmlDoc.DocumentElement.ChildNodes[0].InnerText.ToHexa(true);
				}
				return Global._RSAModulus;
			}
		}
		#endregion

		#region WAMP channels
		internal static IWampChannel IncommingChannel = null, OutgoingChannel = null;
		internal static long IncommingChannelSessionID = 0, OutgoingChannelSessionID = 0;
		internal static bool ChannelsAreClosedBySystem = false;

		static Tuple<string, string, bool> GetLocationInfo()
		{
			var address = UtilityService.GetAppSetting("RouterAddress", "ws://127.0.0.1:26429/");
			var realm = UtilityService.GetAppSetting("RouterRealm", "VIEAppsRealm");
			var mode = UtilityService.GetAppSetting("RouterChannelsMode", "MsgPack");
			return new Tuple<string, string, bool>(address, realm, mode.IsEquals("json"));
		}

		internal static async Task OpenIncomingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (Global.IncommingChannel != null)
				return;

			var info = Global.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			Global.IncommingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			Global.IncommingChannel.RealmProxy.Monitor.ConnectionEstablished += (sender, arguments) =>
			{
				Global.IncommingChannelSessionID = arguments.SessionId;
			};

			if (onConnectionEstablished != null)
				Global.IncommingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				Global.IncommingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				Global.IncommingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await Global.IncommingChannel.Open();
		}

		internal static void CloseIncomingChannel()
		{
			if (Global.IncommingChannel != null)
			{
				Global.IncommingChannel.Close("The incoming channel is closed when stop the API Gateway REST Service", new GoodbyeDetails());
				Global.IncommingChannel = null;
			}
		}

		internal static void ReOpenIncomingChannel(int delay = 0, System.Action onSuccess = null, Action<Exception> onError = null)
		{
			if (Global.IncommingChannel != null)
				(new WampChannelReconnector(Global.IncommingChannel, async () =>
				{
					await Task.Delay(delay > 0 ? delay : 0);
					try
					{
						await Global.IncommingChannel.Open();
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				})).Start();
		}

		internal static async Task OpenOutgoingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (Global.OutgoingChannel != null)
				return;

			var info = Global.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			Global.OutgoingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			Global.OutgoingChannel.RealmProxy.Monitor.ConnectionEstablished += (sender, arguments) =>
			{
				Global.OutgoingChannelSessionID = arguments.SessionId;
			};

			if (onConnectionEstablished != null)
				Global.OutgoingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				Global.OutgoingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				Global.OutgoingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await Global.OutgoingChannel.Open();
		}

		internal static void CloseOutgoingChannel()
		{
			if (Global.OutgoingChannel != null)
			{
				Global.OutgoingChannel.Close("The outgoing channel is closed when stop the API Gateway REST Service", new GoodbyeDetails());
				Global.OutgoingChannel = null;
			}
		}

		internal static void ReOpenOutgoingChannel(int delay = 0, System.Action onSuccess = null, Action<Exception> onError = null)
		{
			if (Global.OutgoingChannel != null)
				(new WampChannelReconnector(Global.OutgoingChannel, async () =>
				{
					await Task.Delay(delay > 0 ? delay : 0);
					try
					{
						await Global.OutgoingChannel.Open();
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				})).Start();
		}

		internal static async Task OpenChannelsAsync()
		{
			await Global.OpenIncomingChannelAsync(
				(sender, arguments) => {
					Global.WriteLogs("The incoming connection is established - Session ID: " + arguments.SessionId);
				},
				(sender, arguments) => {
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLogs("The incoming connection is broken because the router is not found or the router is refused - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
					else
					{
						if (Global.ChannelsAreClosedBySystem)
							Global.WriteLogs("The incoming connection is closed - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
						else
							Global.ReOpenIncomingChannel(
								123,
								() => {
									Global.WriteLogs("Re-connect the incoming connection successful");
								},
								(ex) => {
									Global.WriteLogs("Error occurred while re-connecting the incoming connection", ex);
								}
							);
					}
				},
				(sender, arguments) => {
					Global.WriteLogs("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);

			await Global.OpenOutgoingChannelAsync(
				(sender, arguments) => {
					Global.WriteLogs("The outgoing connection is established - Session ID: " + arguments.SessionId);
				},
				(sender, arguments) => {
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLogs("The outgoing connection is broken because the router is not found or the router is refused - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
					else
					{
						if (Global.ChannelsAreClosedBySystem)
							Global.WriteLogs("The outgoing connection is closed - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
						else
							Global.ReOpenOutgoingChannel(
								123,
								() => {
									Global.WriteLogs("Re-connect the outgoing connection successful");
								},
								(ex) => {
									Global.WriteLogs("Error occurred while re-connecting the outgoing connection", ex);
								}
							);
					}
				},
				(sender, arguments) => {
					Global.WriteLogs("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);
		}
		#endregion

		#region Working with logs
		internal static string GetCorrelationID(IDictionary items)
		{
			if (items == null)
				return UtilityService.GetUUID();

			var id = items.Contains("Correlation-ID")
				? items["Correlation-ID"] as string
				: null;

			if (string.IsNullOrWhiteSpace(id))
			{
				id = UtilityService.GetUUID();
				items.Add("Correlation-ID", id);
			}

			return id;
		}

		internal static string GetCorrelationID()
		{
			return Global.GetCorrelationID(HttpContext.Current?.Items);
		}

		static IManagementService ManagementService = null;

		internal static async Task InitializeManagementServiceAsync()
		{
			if (Global.ManagementService == null)
			{
				await Global.OpenOutgoingChannelAsync();
				Global.ManagementService = Global.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IManagementService>();
			}
		}

		internal static async Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, string simpleStack, string fullStack)
		{
			try
			{
				await Global.InitializeManagementServiceAsync();
				await Global.ManagementService.WriteLogsAsync(correlationID, serviceName, objectName, logs, simpleStack, fullStack, Global.CancellationTokenSource.Token);
			}
			catch { }
		}

		internal static void WriteLogs(string correlationID, string serviceName, string objectName, List<string> logs, string simpleStack, string fullStack)
		{
			Task.Run(async () =>
			{
				await Global.WriteLogsAsync(correlationID, serviceName, objectName, logs, simpleStack, fullStack);
			}).ConfigureAwait(false);
		}

		internal static async Task WriteLogsAsync(string correlationID, string objectName, List<string> logs, Exception exception = null, string serviceName = null)
		{
			// prepare
			serviceName = string.IsNullOrWhiteSpace(serviceName)
					? "APIGateway"
					: serviceName;

			var simpleStack = exception != null
				? exception.StackTrace
				: "";

			var fullStack = "";
			if (exception != null)
			{
				fullStack = exception.StackTrace;
				var inner = exception.InnerException;
				var counter = 0;
				while (inner != null)
				{
					counter++;
					fullStack += "\r\n" + "-> Inner (" + counter.ToString() + "): ---->>>>" + "\r\n" + inner.StackTrace;
					inner = inner.InnerException;
				}
				fullStack += "\r\n" + "-------------------------------------" + "\r\n";
			}

			// write logs
			await Global.WriteLogsAsync(correlationID, serviceName, objectName, logs, simpleStack, fullStack);
		}

		internal static async Task WriteLogsAsync(string correlationID, string objectName, string log, Exception exception = null)
		{
			var logs = !string.IsNullOrEmpty(log)
				? new List<string>() { log }
				: exception != null
					? new List<string>() { exception.Message + " [" + exception.GetType().ToString() + "]" }
					: new List<string>();
			await Global.WriteLogsAsync(correlationID, objectName, logs, exception);
		}

		internal static async Task WriteLogsAsync(List<string> logs, Exception exception = null)
		{
			await Global.WriteLogsAsync(Global.GetCorrelationID(), null, logs, exception);
		}

		internal static async Task WriteLogsAsync(string log, Exception exception = null)
		{
			await Global.WriteLogsAsync(Global.GetCorrelationID(), null, log, exception);
		}

		internal static void WriteLogs(string correlationID, string objectName, List<string> logs, Exception exception = null, string serviceName = null)
		{
			Task.Run(async () =>
			{
				await Global.WriteLogsAsync(correlationID, objectName, logs, exception, serviceName);
			}).ConfigureAwait(false);
		}

		internal static void WriteLogs(string correlationID, string objectName, string log, Exception exception = null)
		{
			var logs = !string.IsNullOrEmpty(log)
				? new List<string>() { log }
				: exception != null
					? new List<string>() { exception.Message + " [" + exception.GetType().ToString() + "]" }
					: new List<string>();
			Global.WriteLogs(correlationID, objectName, logs, exception);
		}

		internal static void WriteLogs(List<string> logs, Exception exception = null)
		{
			Global.WriteLogs(Global.GetCorrelationID(), null, logs, exception);
		}

		internal static void WriteLogs(string log, Exception exception = null)
		{
			Global.WriteLogs(Global.GetCorrelationID(), null, log, exception);
		}
		#endregion

		#region Start/End the app
		internal static HashSet<string> HiddenSegments = null, BypassSegments = null, StaticSegments = null;

		internal static void OnAppStart(HttpContext context)
		{
			var stopwatch = new Stopwatch();
			stopwatch.Start();

			// Json.NET
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
			{
				Formatting = Formatting.Indented,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// open WAMP channels
			Task.Run(async () =>
			{
				await Global.OpenChannelsAsync();
			}).ConfigureAwait(false);

			// special segments
			var segments = UtilityService.GetAppSetting("BypassSegments");
			Global.BypassSegments = string.IsNullOrWhiteSpace(segments)
				? new HashSet<string>()
				: segments.Trim().ToLower().ToHashSet('|', true);

			segments = UtilityService.GetAppSetting("HiddenSegments");
			Global.HiddenSegments = string.IsNullOrWhiteSpace(segments)
				? new HashSet<string>()
				: segments.Trim().ToLower().ToHashSet('|', true);

			segments = UtilityService.GetAppSetting("StaticSegments");
			Global.StaticSegments = string.IsNullOrWhiteSpace(segments)
				? new HashSet<string>()
				: segments.Trim().ToLower().ToHashSet('|', true);

			// handling unhandled exception
			AppDomain.CurrentDomain.UnhandledException += (sender, arguments) =>
			{
				Global.WriteLogs("An unhandled exception is thrown", arguments.ExceptionObject as Exception);
			};

			stopwatch.Stop();
			Global.WriteLogs("*** The API Gateway is ready for serving. The app is initialized in " + stopwatch.GetElapsedTimes());
		}

		internal static void OnAppEnd()
		{
			Global.CancellationTokenSource.Cancel();
			RTU.StopUpdaters();
			Global.ChannelsAreClosedBySystem = true;
			Global.CloseIncomingChannel();
			Global.CloseOutgoingChannel();
		}
		#endregion

		#region Begin/End the request
		internal static void OnAppBeginRequest(HttpApplication app)
		{
			// update default headers to allow access from everywhere
			app.Context.Response.HeaderEncoding = Encoding.UTF8;
			app.Context.Response.Headers.Add("access-control-allow-origin", "*");
			app.Context.Response.Headers.Add("x-correlation-id", Global.GetCorrelationID(app.Context.Items));

			// prepare
			var executionFilePath = app.Request.AppRelativeCurrentExecutionFilePath;
			if (executionFilePath.StartsWith("~/"))
				executionFilePath = executionFilePath.Right(executionFilePath.Length - 2);

			var executionFilePaths = string.IsNullOrEmpty(executionFilePath)
				? new string[] {""}
				: executionFilePath.ToLower().ToArray('/', true);

			// update special headers on OPTIONS request
			if (app.Context.Request.HttpMethod.Equals("OPTIONS"))
			{
				app.Context.Response.Headers.Add("access-control-allow-methods", "HEAD,GET,POST,PUT,DELETE,OPTIONS");

				var allowHeaders = app.Context.Request.Headers.Get("access-control-request-headers");
				if (!string.IsNullOrWhiteSpace(allowHeaders))
					app.Context.Response.Headers.Add("access-control-allow-headers", allowHeaders);

				return;
			}

			// by-pass segments
			else if (Global.BypassSegments.Count > 0 && Global.BypassSegments.Contains(executionFilePaths[0]))
				return;

			// hidden segments
			else if (Global.HiddenSegments.Count > 0 && Global.HiddenSegments.Contains(executionFilePaths[0]))
			{
				Global.ShowError(app.Context, 403, "Forbidden", "AccessDeniedException", null, null);
				app.Context.Response.End();
				return;
			}

			// 403/404 errors
			else if (executionFilePaths[0].IsEquals("global.ashx"))
			{
				var errorElements = app.Context.Request.QueryString != null && app.Context.Request.QueryString.Count > 0
					? app.Context.Request.QueryString.ToString().UrlDecode().ToArray(';')
					: new string[] { "500", "" };
				var errorMessage = errorElements[0].Equals("403")
					? "Forbidden"
					: errorElements[0].Equals("404")
						? "Invalid"
						: "Unknown (" + errorElements[0] + " : " + (errorElements.Length > 1 ? errorElements[1].Replace(":80", "").Replace(":443", "") : "unknown") + ")";
				var errorType = errorElements[0].Equals("403")
					? "AccessDeniedException"
					: errorElements[0].Equals("404")
						? "InvalidRequestException"
						: "Unknown";						
				Global.ShowError(app.Context, errorElements[0].CastAs<int>(), errorMessage, errorType, null, null);
				app.Context.Response.End();
				return;
			}

#if DEBUG || REQUESTLOGS
			var appInfo = app.Context.GetAppInfo();
			Global.WriteLogs(new List<string>() {
					"Begin process [" + app.Context.Request.HttpMethod + "]: " + app.Context.Request.Url.Scheme + "://" + app.Context.Request.Url.Host + app.Context.Request.RawUrl,
					"- Origin: " + appInfo.Item1 + " / " + appInfo.Item2 + " - " + appInfo.Item3,
					"- IP: " + app.Context.Request.UserHostAddress,
					"- Agent: " + app.Context.Request.UserAgent
				});
			if (!executionFilePaths[0].IsEquals("rtu"))
			{
				app.Context.Items["StopWatch"] = new Stopwatch();
				(app.Context.Items["StopWatch"] as Stopwatch).Start();
			}
#endif

			// rewrite url
			var url = app.Request.ApplicationPath + "Global.ashx";
			if (Global.StaticSegments.Contains(executionFilePaths[0]))
				url += "?request-of-static-resource=&path=" + app.Context.Request.RawUrl.UrlEncode();
			else
			{
				url += "?service-name=" + executionFilePaths[0].GetANSIUri();
				if (executionFilePaths.Length > 1)
					url += "&object-name=" + executionFilePaths[1].GetANSIUri();
				if (executionFilePaths.Length > 2)
					url += "&object-identity=" + executionFilePaths[2].GetANSIUri();
			}

			foreach (string key in app.Request.QueryString)
				if (!string.IsNullOrWhiteSpace(key) && !key.IsEquals("service-name") && !key.IsEquals("object-name") && !key.IsEquals("object-identity"))
					url += "&" + key + "=" + app.Request.QueryString[key].UrlEncode();

			app.Context.RewritePath(url);
		}

		internal static void OnAppEndRequest(HttpApplication app)
		{
#if DEBUG || REQUESTLOGS
			if (!app.Context.Request.HttpMethod.Equals("OPTIONS") && app.Context.Items.Contains("StopWatch"))
			{
				(app.Context.Items["StopWatch"] as Stopwatch).Stop();
				var executionTimes = (app.Context.Items["StopWatch"] as Stopwatch).GetElapsedTimes();
				Global.WriteLogs("End process - Execution times: " + executionTimes);
				try
				{
					app.Response.Headers.Add("x-execution-times", executionTimes);
				}
				catch { }
			}
#endif
		}
		#endregion

		#region Pre excute handlers/send headers
		internal static void OnAppPreHandlerExecute(HttpApplication app)
		{
			// check
			if (app.Context.Request.HttpMethod.Equals("OPTIONS") || app.Context.Request.HttpMethod.Equals("HEAD"))
				return;

			// check
			var acceptEncoding = app.Context.Request.Headers["accept-encoding"];
			if (string.IsNullOrWhiteSpace(acceptEncoding))
				return;

			// apply compression
			var previousStream = app.Context.Response.Filter;

			// deflate
			if (acceptEncoding.IsContains("deflate") || acceptEncoding.Equals("*"))
			{
				app.Context.Response.Filter = new DeflateStream(previousStream, CompressionMode.Compress);
				app.Context.Response.Headers.Add("content-encoding", "deflate");
			}

			// gzip
			else if (acceptEncoding.IsContains("gzip"))
			{
				app.Context.Response.Filter = new GZipStream(previousStream, CompressionMode.Compress);
				app.Context.Response.Headers.Add("content-encoding", "gzip");
			}
		}

		internal static void OnAppPreSendHeaders(HttpApplication app)
		{
			// remove un-nessesary headers
			app.Context.Response.Headers.Remove("allow");
			app.Context.Response.Headers.Remove("public");
			app.Context.Response.Headers.Remove("x-powered-by");

			// add special headers
			if (app.Response.Headers["server"] != null)
				app.Response.Headers.Set("server", "VIEApps NGX");
			else
				app.Response.Headers.Add("server", "VIEApps NGX");
		}
		#endregion

		#region Error handlings
		static string ShowErrorStacks = null;

		internal static bool IsShowErrorStacks
		{
			get
			{
				if (string.IsNullOrWhiteSpace(Global.ShowErrorStacks))
#if DEBUG
					Global.ShowErrorStacks = "true";
#else
					Global.ShowErrorStacks = UtilityService.GetAppSetting("ShowErrorStacks", "false");
#endif
				return Global.ShowErrorStacks.IsEquals("true");
			}
		}

		static string SetErrorStatus = null;

		internal static bool IsSetErrorStatus
		{
			get
			{
				if (string.IsNullOrWhiteSpace(Global.SetErrorStatus))
					Global.SetErrorStatus = UtilityService.GetAppSetting("SetErrorStatus", "false");
				return Global.SetErrorStatus.IsEquals("true");
			}
		}

		internal static void ShowError(this HttpContext context, int code, string message, string type, string stack, Exception inner)
		{
			// prepare
			var json = new JObject()
			{
				{ "Message", message.Contains("potentially dangerous") ? "Invalid" : message },
				{ "Type", type },
				{ "Verb", context.Request.HttpMethod },
				{ "CorrelationID", Global.GetCorrelationID(context.Items) }
			};

			if (!string.IsNullOrWhiteSpace(stack) && Global.IsShowErrorStacks)
				json.Add(new JProperty("Stack", stack));

			if (inner != null && Global.IsShowErrorStacks)
			{
				var inners = new JArray();
				var counter = 0;
				var exception = inner;
				while (exception != null)
				{
					counter++;
					inners.Add(new JObject()
					{
						{ "Message", "(" + counter + "): " + exception.Message },
						{ "Type", exception.GetType().ToString() },
						{ "Stack", exception.StackTrace }
					});
					exception = exception.InnerException;
				}

				if (counter > 0)
					json.Add(new JProperty("Inners", inners));
			}

			json = new JObject()
			{
				{ "Status", "Error" },
				{ "Error", json }
			};

			// status code
			if (Global.IsSetErrorStatus)
			{
				context.Response.TrySkipIisCustomErrors = true;
				context.Response.StatusCode = code < 1 ? 500 : code;
			}

			// response with JSON
			context.Response.Cache.SetNoStore();
			context.Response.ContentType = "application/json";
			context.Response.ClearContent();
			context.Response.Output.Write(json.ToString(Global.IsShowErrorStacks ? Formatting.Indented : Formatting.None));

			if (message.Contains("potentially dangerous"))
				context.Response.End();
		}

		static JObject GetJsonException(JObject exception)
		{
			var json = new JObject()
			{
				{ "Message", exception["Message"] },
				{ "Type", exception["ClassName"] },
				{ "Method", exception["ExceptionMethod"] },
				{ "Source", exception["Source"] },
				{ "Stack", exception["StackTraceString"] },
			};

			var inner = exception["InnerException"];
			if (inner != null && inner is JObject)
				json.Add(new JProperty("InnerException", Global.GetJsonException(inner as JObject)));

			return json;
		}

		internal static void ShowError(this HttpContext context, WampException exception, RequestInfo requestInfo = null, bool writeLogs = true)
		{
			var code = 500;
			var message = "";
			var type = "";
			var stack = "";
			Exception inner = null;
			JObject jsonException = null;

			if (exception.ErrorUri.Equals("wamp.error.no_such_procedure") || exception.ErrorUri.Equals("wamp.error.callee_unregistered"))
			{
				if (exception.Arguments != null && exception.Arguments.Length > 0 && exception.Arguments[0] != null && exception.Arguments[0] is JValue)
				{
					message = (exception.Arguments[0] as JValue).Value.ToString();
					var start = message.IndexOf("'");
					var end = message.IndexOf("'", start + 1);
					message = "The requested service is not found [" + message.Substring(start + 1, end - start - 1).Replace("'", "") + "]";
				}
				else
					message = "The requested service is not found";

				type = "ServiceNotFoundException";
				stack = exception.StackTrace;
				inner = exception;
				code = 404;
			}
			else if (exception.ErrorUri.Equals("wamp.error.runtime_error"))
			{
				if (exception.Arguments != null && exception.Arguments.Length > 0 && exception.Arguments[0] != null && exception.Arguments[0] is JObject)
					foreach (var info in exception.Arguments[0] as JObject)
					{
						if (info.Value != null && info.Value is JValue && (info.Value as JValue).Value != null)
							stack += (stack.Equals("") ? "" : "\r\n" + "----- Inner (" + info.Key + ") --------------------" + "\r\n")
								+ (info.Value as JValue).Value.ToString();
					}

				if (requestInfo == null && exception.Arguments != null && exception.Arguments.Length > 2 && exception.Arguments[2] != null && exception.Arguments[2] is JObject)
				{
					var info = (exception.Arguments[2] as JObject).First;
					if (info != null && info is JProperty && (info as JProperty).Name.Equals("RequestInfo") && (info as JProperty).Value != null && (info as JProperty).Value is JObject)
						requestInfo = ((info as JProperty).Value as JToken).FromJson<RequestInfo>();
				}

				jsonException = exception.Arguments != null && exception.Arguments.Length > 4 && exception.Arguments[4] != null && exception.Arguments[4] is JObject
					? Global.GetJsonException(exception.Arguments[4] as JObject)
					: null;

				message = jsonException != null
					? (jsonException["Message"] as JValue).Value.ToString()
					: "Error occurred while processing with the service [net.vieapps.services." + (requestInfo != null ? requestInfo.ServiceName.ToLower() : "unknown") + "]";

				type = jsonException != null
					? (jsonException["Type"] as JValue).Value.ToString().ToArray('.').Last()
					: "ServiceOperationException";

				inner = exception;
			}

			else
			{
				message = exception.Message;
				type = exception.GetType().ToString().ToArray('.').Last();
				stack = exception.StackTrace;
				inner = exception.InnerException;
			}

			// show error
			context.ShowError(code, message, type, stack, inner);

			// write logs
			if (writeLogs)
			{
				var logs = new List<string>() { "[" + type + "]: " + message };

				var fullStack = stack;
				if (requestInfo != null)
					fullStack += "\r\n\r\n" + "==> Request:\r\n" + requestInfo.ToJson().ToString(Formatting.Indented);

				if (jsonException != null)
					fullStack += "\r\n\r\n" + "==> Details:\r\n" + jsonException.ToString(Formatting.Indented);

				var correlationID = requestInfo != null
					? requestInfo.CorrelationID
					: Global.GetCorrelationID(context.Items);
				var serviceName = requestInfo != null
					? requestInfo.ServiceName
					: "unknown";
				var objectName = requestInfo != null
					? requestInfo.ObjectName
					: "unknown";

				Global.WriteLogs(correlationID, serviceName, objectName, logs, exception != null ? exception.StackTrace : "", fullStack);
			}
		}

		internal static void ShowError(this HttpContext context, Exception exception, bool writeLogs = false)
		{
			if (exception is WampException)
				context.ShowError(exception as WampException, null);

			else
			{
				// write logs
				if (writeLogs)
					Global.WriteLogs("", exception);

				// show error
				var type = "Unknown";
				string stack = null;
				Exception inner = null;
				if (exception != null)
				{
					type = exception.GetType().ToString().ToArray('.').Last();
					if (Global.IsShowErrorStacks)
					{
						stack = exception.StackTrace;
						inner = exception.InnerException;
					}
				}
				context.ShowError(exception != null ? exception.GetHttpStatusCode() : 500, exception != null ? exception.Message : "Unknown", type, stack, inner);
			}
		}

		internal static void OnAppError(HttpApplication app)
		{
			var exception = app.Server.GetLastError();
			app.Server.ClearError();
			app.Context.ShowError(exception, true);
		}
		#endregion

		#region Session & User with JSON Web Token
		internal static Session GetSession(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferrer)
		{
			var appInfo = Global.GetAppInfo(header, query, agentString, ipAddress, urlReferrer);
			return new Session()
			{
				IP = ipAddress,
				AppAgent = agentString,
				DeviceID = UtilityService.GetAppParameter("x-device-id", header, query, ""),
				AppName = appInfo.Item1,
				AppPlatform = appInfo.Item2,
				AppOrigin = appInfo.Item3,
			};
		}

		internal static string GetAccessToken(this User user)
		{
			return User.GetAccessToken(user, Global.RSA, Global.AESKey);
		}

		internal static string GetJSONWebToken(this Session session, string accessToken = null)
		{
			return User.GetJSONWebToken(session.User.ID, accessToken ?? session.User.GetAccessToken(), session.SessionID, Global.AESKey, Global.GenerateJWTKey());
		}

		internal static string ParseJSONWebToken(this Session session, string jwt)
		{
			// parse JSON Web Token
			var userID = "";
			var accessToken = "";
			var sessionID = "";
			try
			{
				var info = User.ParseJSONWebToken(jwt, Global.AESKey, Global.GenerateJWTKey());
				userID = info.Item1;
				accessToken = info.Item2;
				sessionID = info.Item3;
			}
			catch (Exception)
			{
				throw;
			}

			// get user information
			try
			{
				session.User = User.ParseAccessToken(accessToken, Global.RSA, Global.AESKey);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Token is invalid (Access token is invalid)", ex);
			}

			if (!session.User.ID.Equals(userID))
				throw new InvalidTokenException("Token is invalid (User identity is invalid)");

			// assign identity of the session
			session.SessionID = sessionID;

			// return access token
			return accessToken;
		}
		#endregion

	}

	// ------------------------------------------------------------------------------

	#region Global.ashx
	public class GlobalHandler : HttpTaskAsyncHandler
	{
		public override bool IsReusable { get { return true; } }

		public override async Task ProcessRequestAsync(HttpContext context)
		{
			// stop process request is OPTIONS
			if (context.Request.HttpMethod.Equals("OPTIONS"))
				return;

			// real-time update
			else if (context.IsWebSocketRequest)
				context.AcceptWebSocketRequest(RTU.ProcessRequestAsync);

			// static resources
			else if (context.Request.QueryString["request-of-static-resource"] != null)
			{
				var path = context.Request.QueryString["path"];
				if (string.IsNullOrWhiteSpace(path))
					path = "~/temp/countries.json";
				else if (path.IndexOf("?") > 0)
					path = path.Left(path.IndexOf("?"));

				try
				{
					var contentType = path.IsEndsWith(".json") || path.IsEndsWith(".js")
						? "application/" + (path.IsEndsWith(".js") ?"javascript" : "json")
							: "text/"
								+ (path.IsEndsWith(".css")
									? "css"
									: path.IsEndsWith(".html") || path.IsEndsWith(".htm")
										? "html"
										: "plain");
					context.Response.Cache.SetNoStore();
					context.Response.ContentType = contentType;
					await context.Response.Output.WriteAsync(await UtilityService.ReadTextFileAsync(context.Server.MapPath(path)));
				}
				catch (FileNotFoundException ex)
				{
					context.ShowError(404, "Not found [" + path + "]", "FileNotFoundException", ex.StackTrace, ex.InnerException);
				}
				catch (Exception ex)
				{
					context.ShowError(ex);
				}
			}

			// APIs
			else
			{
				// prepare
				var serviceName = context.Request.QueryString["service-name"];

				// no information
				if (string.IsNullOrWhiteSpace(serviceName))
					context.ShowError(new InvalidRequestException());

				// external APIs
				else if (ExternalAPIs.APIs.ContainsKey(serviceName))
					await ExternalAPIs.ProcessRequestAsync(context);

				// internal APIs
				else
					await InternalAPIs.ProcessRequestAsync(context);
			}
		}
	}
	#endregion

	#region Global.asax
	public class GlobalApp : HttpApplication
	{

		protected void Application_Start(object sender, EventArgs args)
		{
			Global.OnAppStart(sender as HttpContext);
		}

		protected void Application_BeginRequest(object sender, EventArgs args)
		{
			Global.OnAppBeginRequest(sender as HttpApplication);
		}

		protected void Application_PreRequestHandlerExecute(object sender, EventArgs args)
		{
			Global.OnAppPreHandlerExecute(sender as HttpApplication);
		}

		protected void Application_PreSendRequestHeaders(object sender, EventArgs args)
		{
			Global.OnAppPreSendHeaders(sender as HttpApplication);
		}

		protected void Application_EndRequest(object sender, EventArgs args)
		{
			Global.OnAppEndRequest(sender as HttpApplication);
		}

		protected void Application_Error(object sender, EventArgs args)
		{
			Global.OnAppError(sender as HttpApplication);
		}

		protected void Application_End(object sender, EventArgs args)
		{
			Global.OnAppEnd();
		}
	}
	#endregion

}