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
using System.Net;
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
using net.vieapps.Components.Caching;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class Global
	{

		#region Attributes
		internal static CancellationTokenSource CancellationTokenSource = new CancellationTokenSource();

		internal static IWampChannel IncommingChannel = null, OutgoingChannel = null;
		internal static long IncommingChannelSessionID = 0, OutgoingChannelSessionID = 0;
		internal static bool ChannelsAreClosedBySystem = false;

		internal static IManagementService ManagementService = null;
		internal static IDisposable InterCommunicationMessageUpdater = null;
		internal static IRTUService RTUService = null;

		static Queue<Tuple<string, string, string, List<string>, string, string>> Logs = new Queue<Tuple<string, string, string, List<string>, string, string>>();

		static string _AESKey = null, _JWTKey = null, _PublicJWTKey = null, _RSAKey = null, _RSAExponent = null, _RSAModulus = null;
		static RSACryptoServiceProvider _RSA = null;

		static HashSet<string> QueryExcluded = "service-name,object-name,object-identity,request-of-static-resource".ToHashSet();

		static CacheManager _Cache = new CacheManager("VIEApps-API-Gateway", "Absolute", 120);
		public static CacheManager Cache { get { return Global._Cache; } }
		#endregion

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
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(false, false, 256);
		}

		internal static byte[] GenerateEncryptionIV(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, true, 128);
		}

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

		internal static string GenerateJWTKey()
		{
			if (Global._PublicJWTKey == null)
				Global._PublicJWTKey = Global.JWTKey.GetHMACSHA512(Global.AESKey).ToBase64Url(false, true);
			return Global._PublicJWTKey;
		}

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
				var subject = Global.IncommingChannel?.RealmProxy.Services.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages");
				if (subject != null)
					Global.InterCommunicationMessageUpdater = subject.Subscribe(
						msg => Global.ProcessInterCommunicateMessage(msg),
						ex => Global.WriteLogs(UtilityService.BlankUID, "RTU", "Error occurred while fetching inter-communicate message", ex)
					);
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
				Task.Run(async () =>
				{
					try
					{
						await Global.InitializeManagementServiceAsync();
						await Global.InitializeRTUServiceAsync();
					}
					catch { }
				}).ConfigureAwait(false);
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
					Global.Logs.Enqueue(new Tuple<string, string, string, List<string>, string, string>(UtilityService.NewUID, "APIGateway", null, new List<string>() { "The outgoing connection is established - Session ID: " + arguments.SessionId }, null, null));
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
					Global.WriteLogs("Got an error of outgoing connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
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
				while (Global.Logs.Count > 0)
				{
					var log = Global.Logs.Dequeue();
					await Global.ManagementService.WriteLogsAsync(log.Item1, log.Item2, log.Item3, log.Item4, log.Item5, log.Item6, Global.CancellationTokenSource.Token);
				}
				await Global.ManagementService.WriteLogsAsync(correlationID, serviceName, objectName, logs, simpleStack, fullStack, Global.CancellationTokenSource.Token);
			}
			catch
			{
				Global.Logs.Enqueue(new Tuple<string, string, string, List<string>, string, string>(correlationID, serviceName, objectName, logs, simpleStack, fullStack));
			}
		}

		internal static void WriteLogs(string correlationID, string serviceName, string objectName, List<string> logs, string simpleStack, string fullStack)
		{
			Task.Run(async () =>
			{
				await Global.WriteLogsAsync(correlationID, serviceName, objectName, logs, simpleStack, fullStack);
			}).ConfigureAwait(false);
		}

		internal static Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, Exception exception = null)
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
			return Global.WriteLogsAsync(correlationID, serviceName, objectName, logs, simpleStack, fullStack);
		}

		internal static Task WriteLogsAsync(string correlationID, string objectName, List<string> logs, Exception exception = null)
		{
			return Global.WriteLogsAsync(correlationID, null, objectName, logs, exception);
		}

		internal static Task WriteLogsAsync(string correlationID, string objectName, string log, Exception exception = null)
		{
			var logs = !string.IsNullOrEmpty(log)
				? new List<string>() { log }
				: exception != null
					? new List<string>() { exception.Message + " [" + exception.GetType().ToString() + "]" }
					: new List<string>();
			return Global.WriteLogsAsync(correlationID, objectName, logs, exception);
		}

		internal static Task WriteLogsAsync(List<string> logs, Exception exception = null)
		{
			return Global.WriteLogsAsync(Global.GetCorrelationID(), null, logs, exception);
		}

		internal static Task WriteLogsAsync(string log, Exception exception = null)
		{
			return Global.WriteLogsAsync(Global.GetCorrelationID(), null, log, exception);
		}

		internal static void WriteLogs(string correlationID, string serviceName, string objectName, List<string> logs, Exception exception = null)
		{
			Task.Run(async () =>
			{
				await Global.WriteLogsAsync(correlationID, serviceName, objectName, logs, exception);
			}).ConfigureAwait(false);
		}

		internal static void WriteLogs(string correlationID, string objectName, List<string> logs, Exception exception = null)
		{
			Global.WriteLogs(correlationID, null, objectName, logs, exception);
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
			Global.BypassSegments = UtilityService.GetAppSetting("BypassSegments")?.Trim().ToLower().ToHashSet('|', true) ?? new HashSet<string>();
			Global.HiddenSegments = UtilityService.GetAppSetting("HiddenSegments")?.Trim().ToLower().ToHashSet('|', true) ?? new HashSet<string>();
			Global.StaticSegments = UtilityService.GetAppSetting("StaticSegments")?.Trim().ToLower().ToHashSet('|', true) ?? new HashSet<string>();
			Global.StaticSegments.Append("statics");

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
			Global.InterCommunicationMessageUpdater?.Dispose();
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
				app.Context.Response.Headers.Add("access-control-allow-methods", "GET,POST,PUT,DELETE");

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
				if (!string.IsNullOrWhiteSpace(key) && !Global.QueryExcluded.Contains(key))
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

		internal static void ShowError(this HttpContext context, Exception exception, RequestInfo requestInfo = null, bool writeLogs = false)
		{
			if (exception is WampException)
				context.ShowError(exception as WampException, requestInfo);

			else
			{
				// write logs
				if (writeLogs)
					Global.WriteLogs("", exception);

				// show error
				var message = exception != null ? exception.Message : "Unknown error";
				var type = exception != null ? exception.GetType().ToString().ToArray('.').Last() : "Unknown";
				string stack = exception != null && Global.IsShowErrorStacks ? exception.StackTrace : null;
				Exception inner = exception != null && Global.IsShowErrorStacks ? exception.InnerException : null;
				context.ShowError(exception != null ? exception.GetHttpStatusCode() : 500, message, type, stack, inner);
			}
		}

		internal static void OnAppError(HttpApplication app)
		{
			var exception = app.Server.GetLastError();
			app.Server.ClearError();
			app.Context.ShowError(exception, null, true);
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

		#region Send & process inter-communicate message
		static async Task InitializeRTUServiceAsync()
		{
			if (Global.RTUService == null)
			{
				await Global.OpenOutgoingChannelAsync();
				Global.RTUService = Global.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IRTUService>();
			}
		}

		internal static async Task SendInterCommunicateMessageAsync(CommunicateMessage message)
		{
			try
			{
				await Global.InitializeRTUServiceAsync();
				await Global.RTUService.SendInterCommunicateMessageAsync(message, Global.CancellationTokenSource.Token);
			}
			catch { }
		}

		static void ProcessInterCommunicateMessage(CommunicateMessage message)
		{

		}
		#endregion

	}

	// ------------------------------------------------------------------------------

	#region Global.ashx
	public class GlobalHandler : HttpTaskAsyncHandler
	{
		public GlobalHandler() : base() { }

		public override bool IsReusable { get { return true; } }

		public override async Task ProcessRequestAsync(HttpContext context)
		{
			// stop process request is OPTIONS
			if (context.Request.HttpMethod.Equals("OPTIONS"))
				return;

			// real-time update
			if (context.IsWebSocketRequest)
				context.AcceptWebSocketRequest(RTU.ProcessRequestAsync);

			// static resources
			else if (context.Request.QueryString["request-of-static-resource"] != null)
			{
				// check "If-Modified-Since" request to reduce traffict
				var eTag = "StaticResource#" + context.Request.RawUrl.ToLower().GetMD5();
				if (context.Request.Headers["If-Modified-Since"] != null && eTag.Equals(context.Request.Headers["If-None-Match"]))
				{
					context.Response.Cache.SetCacheability(HttpCacheability.Public);
					context.Response.StatusCode = (int)HttpStatusCode.NotModified;
					context.Response.StatusDescription = "Not Modified";
					context.Response.Headers.Add("ETag", "\"" + eTag + "\"");
					return;
				}

				// prepare
				var path = context.Request.QueryString["path"];
				if (string.IsNullOrWhiteSpace(path))
					path = "~/data-files/statics/countries.json";

				if (path.IndexOf("?") > 0)
					path = path.Left(path.IndexOf("?"));

				// process
				try
				{
					// get information of the requested file
					var filePath = "";
					if (!path.IsStartsWith("/statics/"))
						filePath = context.Server.MapPath(path);

					else
					{
						filePath = UtilityService.GetAppSetting("StaticFilesPath");
						if (string.IsNullOrEmpty(filePath))
							filePath = HttpRuntime.AppDomainAppPath + @"\data-files\statics";
						if (filePath.EndsWith(@"\"))
							filePath = filePath.Left(filePath.Length - 1);

						filePath += path.Replace("/statics/", "/").Replace("/", @"\");
					}

					// check exist
					var fileInfo = new FileInfo(filePath);
					if (!fileInfo.Exists)
						throw new FileNotFoundException();

					// set cache policy
					context.Response.Cache.SetCacheability(HttpCacheability.Public);
					context.Response.Cache.SetExpires(DateTime.Now.AddDays(1));
					context.Response.Cache.SetSlidingExpiration(true);
					context.Response.Cache.SetOmitVaryStar(true);
					context.Response.Cache.SetValidUntilExpires(true);
					context.Response.Cache.SetLastModified(fileInfo.LastWriteTime);
					context.Response.Cache.SetETag(eTag);

					// write content
					var contentType = path.IsEndsWith(".json") || path.IsEndsWith(".js")
						? "application/" + (path.IsEndsWith(".js") ?"javascript" : "json")
							: "text/"
								+ (path.IsEndsWith(".css")
									? "css"
									: path.IsEndsWith(".html") || path.IsEndsWith(".htm")
										? "html"
										: "plain");
					var staticContent = await UtilityService.ReadTextFileAsync(fileInfo.FullName);
					context.Response.ContentType = contentType;
					await context.Response.Output.WriteAsync(contentType.IsEquals("application/json") ? JObject.Parse(staticContent).ToString(Formatting.Indented) : staticContent);
				}
				catch (FileNotFoundException ex)
				{
					context.ShowError((int)HttpStatusCode.NotFound, "Not found [" + path + "]", "FileNotFoundException", ex.StackTrace, ex.InnerException);
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