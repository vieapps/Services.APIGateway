using System;
using System.Linq;
using System.Net;
using System.IO;
using System.Reflection;
using System.Configuration;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using WampSharp.V2;
using WampSharp.V2.Realm;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace net.vieapps.Services.APIGateway
{
	public class RouterComponent
	{
		public const string Powered = "WAMP#v20.1.1-SSL+rev:2020.02.19-lts.targets";

		public IWampHost Host { get; private set; } = null;

		public IWampHostedRealm HostedRealm { get; private set; } = null;

		public string Address { get; set; } = null;

		public string Realm { get; set; } = null;

		public X509Certificate2 SslCertificate { get; set; } = null;

		public SslProtocols SslProtocol { get; set; } = SslProtocols.Tls12;

		public ConcurrentDictionary<long, SessionInfo> Sessions { get; } = new ConcurrentDictionary<long, SessionInfo>();

		public bool IsUserInteractive { get; private set; } = false;

		public Action<Exception> OnError { get; set; } = null;

		public Action OnStarted { get; set; } = null;

		public Action OnStopped { get; set; } = null;

		public Action<SessionInfo> OnSessionCreated { get; set; } = null;

		public Action<SessionInfo> OnSessionClosed { get; set; } = null;

		Fleck.WebSocketServer StatisticsServer { get; set; } = null;

		public void Start(string[] args)
		{
			// prepare
			this.IsUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(a => a.StartsWith("/daemon")) == null;

			if (string.IsNullOrWhiteSpace(this.Address) || string.IsNullOrWhiteSpace(this.Realm))
			{
				this.Address = args?.FirstOrDefault(a => a.StartsWith("/address:"));
				if (string.IsNullOrWhiteSpace(this.Address))
					this.Address = ConfigurationManager.AppSettings["Address"];
				else
					this.Address = this.Address.Substring(this.Address.IndexOf(":") + 1).Trim();

				if (string.IsNullOrWhiteSpace(this.Address))
					this.Address = "ws://0.0.0.0:16429/";
				else if (!this.Address.EndsWith("/"))
					this.Address += "/";

				this.Realm = args?.FirstOrDefault(a => a.StartsWith("/realm:"));
				if (string.IsNullOrWhiteSpace(this.Realm))
					this.Realm = ConfigurationManager.AppSettings["Realm"];
				else
					this.Realm = this.Realm.Substring(this.Realm.IndexOf(":") + 1).Trim();

				if (string.IsNullOrWhiteSpace(this.Realm))
					this.Realm = "VIEAppsRealm";

				var sslCertificateFilePath = ConfigurationManager.AppSettings["SslCertificate:FilePath"];
				if (!string.IsNullOrWhiteSpace(sslCertificateFilePath) && sslCertificateFilePath.EndsWith(".pfx") && File.Exists(sslCertificateFilePath))
					try
					{
						var sslCertificatePassword = ConfigurationManager.AppSettings["SslCertificate:Password"];
						this.SslCertificate = sslCertificatePassword != null
							? new X509Certificate2(sslCertificateFilePath, sslCertificatePassword, X509KeyStorageFlags.UserKeySet)
							: new X509Certificate2(sslCertificateFilePath);

						this.SslProtocol = Enum.TryParse(ConfigurationManager.AppSettings["SslProtocol"] ?? "Tls12", out SslProtocols sslProtocol)
							? sslProtocol
							: SslProtocols.Tls12;
					}
					catch (Exception ex)
					{
						this.OnError?.Invoke(ex);
					}
			}

			void startRouter()
			{
				try
				{
					this.Host = this.SslCertificate != null
						? new DefaultWampHost(this.Address.Replace("ws://", "wss://"), null, null, null, this.SslCertificate, () => this.SslProtocol)
						: new DefaultWampHost(this.Address.Replace("wss://", "ws://"));

					this.HostedRealm = this.Host.RealmContainer.GetRealmByName(this.Realm);
					this.HostedRealm.SessionCreated += (sender, arguments) =>
					{
						var details = arguments.HelloDetails.TransportDetails;
						var type = details.GetType();
						var property = type.GetProperty("Peer", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
						var peer = property != null && property.CanRead
							? property.GetValue(details)
							: null;
						var uri = peer != null ? new Uri(peer as string) : null;
						property = type.GetProperty("Id", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
						var id = property != null && property.CanRead
							? property.GetValue(details)
							: null;
						var sessionInfo = new SessionInfo
						{
							SessionID = arguments.SessionId,
							ConnectionID = id != null ? (Guid)id : Guid.NewGuid(),
							EndPoint = new IPEndPoint(IPAddress.TryParse(uri?.Host ?? "0.0.0.0", out var ipAddress) ? ipAddress : IPAddress.Parse("0.0.0.0"), uri != null ? uri.Port : 16429)
						};
						this.Sessions.TryAdd(arguments.SessionId, sessionInfo);
						this.OnSessionCreated?.Invoke(sessionInfo);
					};
					this.HostedRealm.SessionClosed += (sender, arguments) =>
					{
						if (this.Sessions.TryRemove(arguments.SessionId, out var sessionInfo))
						{
							sessionInfo.CloseType = arguments.CloseType.ToString();
							sessionInfo.CloseReason = arguments.Reason;
						}
						this.OnSessionClosed?.Invoke(sessionInfo);
					};

					this.Host.Open();
				}
				catch (Exception ex)
				{
					var message = $"Cannot start the router => {ex.Message}";
					if (ex is SocketException && ex.Message.StartsWith("Address already in use"))
						message = $"Cannot start the router (because the port is already in use by another app) => Please make sure no app use the port {new Uri(this.Address).Port}";
					this.OnError?.Invoke(new Exception(message, ex));
				}
			}

			void startStatisticServer()
			{
				var address = $"{(this.SslCertificate != null ? "wss" : "ws")}://0.0.0.0:{(Int32.TryParse(ConfigurationManager.AppSettings["StatisticsWebSocketServer:Port"] ?? "56429", out var port) ? port : 56429)}/ ";
				try
				{
					this.StatisticsServer = new Fleck.WebSocketServer(address)
					{
						Certificate = this.SslCertificate,
						EnabledSslProtocols = this.SslProtocol
					};

					this.StatisticsServer.Start(websocket =>
					{
						websocket.OnMessage = message =>
						{
							try
							{
								var json = JObject.Parse(message);
								var command = json.Value<string>("Command") ?? "Unknown";

								if (command.ToLower().Equals("info"))
									Task.Run(() => websocket.Send(this.RouterInfo.ToString(Formatting.None))).ConfigureAwait(false);

								else if (command.ToLower().Equals("connections"))
									Task.Run(() => websocket.Send(new JObject
									{
										{ "Connections", this.Sessions.Count }
									}.ToString(Formatting.None))).ConfigureAwait(false);

								else if (command.ToLower().Equals("sessions"))
									Task.Run(() => websocket.Send(this.SessionsInfo.ToString(Formatting.None))).ConfigureAwait(false);

								else if (command.ToLower().Equals("session"))
								{
									if (this.Sessions.TryGetValue(json.Value<long>("SessionID"), out var sessionInfo))
										Task.Run(() => websocket.Send(sessionInfo.ToJson().ToString(Formatting.None))).ConfigureAwait(false);
									else
										Task.Run(() => websocket.Send(new JObject
										{
											{ "Error", $"Not Found" }
										}.ToString(Formatting.None))).ConfigureAwait(false);
								}

								else if (command.ToLower().Equals("update"))
								{
									if (this.Sessions.TryGetValue(json.Value<long>("SessionID"), out var sessionInfo))
									{
										sessionInfo.Name = json.Value<string>("Name");
										sessionInfo.Description = json.Value<string>("Description");
									}
								}

								else
									Task.Run(() => websocket.Send(new JObject
									{
										{ "Error", $"Unknown command [{message}]" }
									}.ToString(Formatting.None))).ConfigureAwait(false);
							}
							catch (Exception ex)
							{
								Task.Run(() => websocket.Send(new JObject
								{
									{ "Error", $"Bad command [{message}] => {ex.Message}" }
								}.ToString(Formatting.None))).ConfigureAwait(false);
							}
						};
					});
				}
				catch (Exception ex)
				{
					var message = $"Cannot start the statistics server => {ex.Message}";
					if (ex is SocketException && ex.Message.StartsWith("Address already in use"))
						message = $"Cannot start the statistics server (because the port is already in use by another app) => Please make sure no app use the port {new Uri(address).Port}";
					this.OnError?.Invoke(new Exception(message, ex));
					this.StatisticsServer = null;
				}
			}

			// start
			startRouter();
			if (this.Host != null)
			{
				if ("true".Equals(ConfigurationManager.AppSettings["StatisticsWebSocketServer:Enable"] ?? "true"))
					startStatisticServer();
				this.OnStarted?.Invoke();
			}
		}

		public void Stop()
		{
			try
			{
				this.HostedRealm = null;
				this.Host?.Dispose();
				this.StatisticsServer?.Dispose();
				this.OnStopped?.Invoke();
			}
			catch (Exception ex)
			{
				this.OnError?.Invoke(ex);
			}
		}

		public JObject RouterInfo => new JObject
		{
			{ "ProcessID", $"{Process.GetCurrentProcess().Id}" },
			{ "WorkingMode", this.IsUserInteractive ? "Interactive app" : "Background service" },
			{ "UseSecuredConnections", $"{this.SslCertificate != null}".ToLower() + (this.SslCertificate != null ? $" (Issued by {this.SslCertificate.GetNameInfo(X509NameType.DnsName, true)})" : "") },
			{ "ListeningURI", $"{(this.SslCertificate != null ? this.Address.Replace("ws://", "wss://") : this.Address.Replace("wss://", "ws://"))}{this.Realm}" },
			{ "HostedRealmSessionID", $"{this.HostedRealm.SessionId}" },
			{ "StatisticsServer", $"{this.StatisticsServer != null}".ToLower() },
			{ "StatisticsServerPort", this.StatisticsServer != null ? this.StatisticsServer.Port : 56429 },
			{ "Platform", $"{RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})" },
			{ "Powered", RouterComponent.Powered }
		};

		public string RouterInfoString
		{
			get
			{
				var json = this.RouterInfo;
				return
					$"- Process ID: {json.Value<string>("ProcessID")}" + "\r\n\t" +
					$"- Working Mode: {json.Value<string>("WorkingMode")}" + "\r\n\t" +
					$"- Use Secured Connections: {json.Value<string>("UseSecuredConnections")}" + "\r\n\t" +
					$"- Listening URI: {json.Value<string>("ListeningURI")}" + "\r\n\t" +
					$"- Hosted Realm Session ID: {json.Value<string>("HostedRealmSessionID")}" + "\r\n\t" +
					$"- Statistics Server: {json.Value<string>("StatisticsServer")}" + "\r\n\t" +
					$"- Statistics Server Port: {json.Value<long>("StatisticsServerPort")}" + "\r\n\t" +
					$"- Platform: {json.Value<string>("Platform")}" + "\r\n\t" +
					$"- Powered: {json.Value<string>("Powered")}";
			}
		}

		public JObject SessionsInfo
		{
			get
			{
				var sessions = new JArray();
				this.Sessions.Values.ToList().ForEach(info => sessions.Add(info.ToJson()));
				return new JObject
				{
					{ "Total", this.Sessions.Count },
					{ "Sessions", sessions }
				};
			}
		}

		public string SessionsInfoString
		{
			get
			{
				var json = this.SessionsInfo;
				var sessions = json["Sessions"] as JArray;
				var info = $"Total: {json.Value<long>("Total")}";
				if (sessions.Count > 0)
				{
					info += "\r\n" + "Details:";
					foreach (JObject session in sessions)
						info += "\r\n\t" + $"Session ID: {session.Value<long>("SessionID")} - Connection Info: {session.Value<string>("ConnectionID")} - {session.Value<string>("EndPoint")})";
				}
				return info;
			}
		}

		~RouterComponent()
		{
			try
			{
				this.Stop();
			}
			catch { }
		}
	}

	public class SessionInfo
	{
		public long SessionID { get; internal set; }

		public Guid ConnectionID { get; internal set; }

		public IPEndPoint EndPoint { get; internal set; }

		public string Name { get; internal set; }

		public string Description { get; internal set; }

		public string CloseType { get; internal set; }

		public string CloseReason { get; internal set; }

		internal JObject ToJson() => new JObject
		{
			{ "SessionID", this.SessionID },
			{ "ConnectionID", $"{this.ConnectionID}" },
			{ "EndPoint", $"{this.EndPoint}" },
			{ "Name", this.Name },
			{ "Description", this.Description }
		};
	}
}