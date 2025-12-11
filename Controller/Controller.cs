#region Related components
using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using System.Configuration;
using System.Reflection;
using System.Runtime.InteropServices;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Realm;
using WampSharp.V2.Client;
using WampSharp.V2.Core.Contracts;
using net.vieapps.Components.Utility;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class Controller : IController, IDisposable
	{
		/// <summary>
		/// Creates new instance of services controller
		/// </summary>
		/// <param name="cancellationToken">The cancellation token</param>
		public Controller(CancellationToken cancellationToken = default)
			=> this.CancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

		public async Task DisposeAsync()
		{
			if (!this.IsDisposed)
			{
				this.IsDisposed = true;
				await this.StopAsync().ConfigureAwait(false);
				this.CancellationTokenSource.Dispose();
				Global.OnProcess?.Invoke($"The API Gateway Controller was disposed");
				await Task.Delay(123).ConfigureAwait(false);
			}
		}

		public void Dispose()
		{
			GC.SuppressFinalize(this);
			this.DisposeAsync().Execute(true);
		}

		~Controller()
			=> this.Dispose();

		#region Process Info
		public class ProcessInfo
		{
			public ProcessInfo(string id, string executable, string arguments, string recycleAt, Dictionary<string, object> extra = null)
			{
				this.ID = id;
				this.Executable = executable;
				this.Arguments = arguments;
				this.RecycleAt = string.IsNullOrWhiteSpace(recycleAt) || !DateTime.TryParse($"{DateTime.Now:yyyy/MM/dd} {recycleAt}", out var datetime) ? null as DateTime? : datetime < DateTime.Now ? datetime.AddDays(1) : datetime;
				this.Extra = new Dictionary<string, object>(extra ?? new Dictionary<string, object>(), StringComparer.OrdinalIgnoreCase);
			}

			public string ID { get; }

			public string Executable { get; }

			public string Arguments { get; }

			public DateTime? RecycleAt { get; internal set; }

			public Dictionary<string, object> Extra { get; }

			public ExternalProcess.Info Instance { get; internal set; }

			public void Set<T>(string name, T value)
				=> this.Extra[name] = value;

			public void Set<T>(IDictionary<string, T> items)
				=> items?.ForEach(kvp => this.Set(kvp.Key, kvp.Value));

			public T Get<T>(string name, T @default = default)
				=> this.Extra.TryGetValue(name, out var value) && value != null && value is T val
					? val
					: @default;
		}
		#endregion

		#region Properties
		public ServiceState State { get; private set; } = ServiceState.Initializing;

		public ControllerInfo Info { get; private set; }

		public CancellationTokenSource CancellationTokenSource { get; private set; }

		public CancellationToken CancellationToken => this.CancellationTokenSource.Token;

		IDisposable InterCommunicator { get; set; }

		IDisposable UpdateCommunicator { get; set; }

		IAsyncDisposable ManagingService { get; set; }

		DateTime LogFlusherTime { get; set; } = DateTime.Now;

		ExternalProcess.Info LogFlusher { get; set; }

		IAsyncDisposable MessagingService { get; set; }

		List<IDisposable> Timers { get; } = new List<IDisposable>();

		Dictionary<string, ProcessInfo> Tasks { get; } = new Dictionary<string, ProcessInfo>(StringComparer.OrdinalIgnoreCase);

		string WorkingDirectory { get; } = $"{Directory.GetCurrentDirectory()}{Path.DirectorySeparatorChar}";

		string ServiceHosting { get; set; } = "VIEApps.Services.APIGateway";

		Dictionary<string, ProcessInfo> BusinessServices { get; } = new Dictionary<string, ProcessInfo>(StringComparer.OrdinalIgnoreCase);

		MailSender MailSender { get; set; }

		WebHookSender WebHookSender { get; set; }

		bool AllowRegisterBusinessServices { get; set; } = true;

		bool AllowRegisterHelperServices { get; set; } = true;

		bool AllowRegisterHelperTimers { get; set; } = true;

		bool IsHouseKeeperRunning { get; set; } = false;

		bool IsTaskSchedulerRunning { get; set; } = false;

		public bool IsDisposed { get; private set; } = false;

		bool IsUserInteractive { get; set; } = false;

		bool IsWindows { get; } = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

		bool IsTimers { get; } = "true".IsEquals(UtilityService.GetAppSetting("Controller:Timers", "true"));

		DateTime ClientPingTime { get; set; } = DateTime.Now;

		int PingInterval { get; } = Int32.TryParse(UtilityService.GetAppSetting("Controller:Timers:Interval:Ping", "120"), out var interval) && interval > 0 ? interval : 120;

		DateTime ClientSchedulingTime { get; set; } = DateTime.Now;

		int SchedulingInterval { get; } = Int32.TryParse(UtilityService.GetAppSetting("Controller:Timers:Interval:Scheduler", "900"), out var interval) && interval > 0 ? interval : 900;

		int FlushingInterval { get; } = Int32.TryParse(UtilityService.GetAppSetting("Controller:Timers:Interval:FlushLogs", "13"), out var interval) && interval > 0 ? interval : 13;

		List<string> VersionDataSources { get; } = new List<string>();

		List<string> TrashDataSources { get; } = new List<string>();

		List<string> HttpServices = new List<string> { "APIs", "Files", "Portals", "CMSPortals" };

		/// <summary>
		/// Gets the number of scheduling tasks
		/// </summary>
		public int NumberOfTasks => this.Tasks.Count;

		/// <summary>
		/// Gets the number of scheduling timers
		/// </summary>
		public int NumberOfTimers => this.Timers.Count;
		#endregion

		#region Start/Stop controller
		/// <summary>
		/// Starts the API Gateway Controller
		/// </summary>
		/// <param name="args">The arguments</param>
		/// <param name="onIncomingConnectionEstablished">The action to fire when the incomming connection is established</param>
		/// <param name="onOutgoingConnectionEstablished">The action to fire when the outgoing connection is established</param>
		/// <param name="next">The next action to run when the controller was started</param>
		public void Start(string[] args = null, Action<object, WampSessionCreatedEventArgs> onIncomingConnectionEstablished = null, Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished = null, Action<Controller> next = null)
		{
			// prepare arguments
			var stopwatch = Stopwatch.StartNew();
			this.IsUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(a => a.IsStartsWith("/daemon")) == null;

			var mode = this.IsUserInteractive ? "Interactive app" : "Background service";
			var (user, host, platform, os) = Extensions.GetRuntimeArguments();

			this.Info = new ControllerInfo
			{
				ID = $"{user}-{host}-" + $"{platform}{os}{mode}".ToLower().GenerateUUID(),
				User = user,
				Host = host,
				Platform = Extensions.GetRuntimePlatform(),
				Mode = mode,
				Available = true
			};
			Global.NodeID = this.Info.ID;

			if (args?.FirstOrDefault(arg => arg.IsStartsWith("/no-business-services")) != null || "false".IsEquals(UtilityService.GetAppSetting("Controller:Services")))
				this.AllowRegisterBusinessServices = false;

			if (args?.FirstOrDefault(arg => arg.IsStartsWith("/no-helper-services")) != null || "false".IsEquals(UtilityService.GetAppSetting("Controller:Helper:Services")))
				this.AllowRegisterHelperServices = false;

			if (args?.FirstOrDefault(arg => arg.IsStartsWith("/no-helper-timers")) != null || "false".IsEquals(UtilityService.GetAppSetting("Controller:Helper:Timers")))
				this.AllowRegisterHelperTimers = false;

			// prepare directories
			try
			{
				new[]
				{
					Global.StatusPath,
					Global.LogsPath,
					Global.TempPath,
					MailSender.EmailsPath,
					WebHookSender.WebHooksPath
				}.Where(path => !Directory.Exists(path)).ForEach(path => Directory.CreateDirectory(path));
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Error occurred while preparing directories => {ex.Message}", ex);
			}

			// prepare services
			if (ConfigurationManager.GetSection(UtilityService.GetAppSetting("Section:Services", "net.vieapps.services")) is AppConfigurationSectionHandler servicesConfiguration)
			{
				this.ServiceHosting = servicesConfiguration.Section.Attributes["executable"]?.Value.Trim() ?? this.ServiceHosting;
				if (this.ServiceHosting.IsEndsWith(".exe") || this.ServiceHosting.IsEndsWith(".dll"))
					this.ServiceHosting = this.ServiceHosting.Left(this.ServiceHosting.Length - 4).Trim();
				if (servicesConfiguration.Section.SelectNodes("./add") is XmlNodeList services)
					services.ToList().ForEach(service =>
					{
						var name = service.Attributes["name"]?.Value?.Trim().ToLower();
						var type = service.Attributes["type"]?.Value?.Trim().Replace(" ", "");
						if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(type))
							this.BusinessServices[name] = new ProcessInfo(name, service.Attributes["executable"]?.Value?.Trim(), $"{type} {service.Attributes["arguments"]?.Value}".Trim(), service.Attributes["recycleAt"]?.Value?.Trim());
					});
			}

			// prepare scheduling tasks
			if (ConfigurationManager.GetSection(UtilityService.GetAppSetting("Section:TaskScheduler", "net.vieapps.task.scheduler")) is AppConfigurationSectionHandler taskSchedulerConfiguration && taskSchedulerConfiguration.Section.SelectNodes("task") is XmlNodeList taskSchedulers)
				taskSchedulers.ToList().ForEach(taskScheduler =>
				{
					var executable = taskScheduler.Attributes["executable"]?.Value.Trim();
					if (!string.IsNullOrWhiteSpace(executable) && File.Exists(executable))
					{
						var arguments = (taskScheduler.Attributes["arguments"]?.Value ?? "").Trim();
						var id = (executable + " " + arguments).ToLower().GenerateUUID();
						this.Tasks[id] = new ProcessInfo(id, executable, arguments, null, new Dictionary<string, object>
						{
							{ "Time", Int32.TryParse(taskScheduler.Attributes["time"]?.Value, out var time) ? time.ToString() : taskScheduler.Attributes["time"]?.Value ?? "3" }
						});
					}
				});

			// start
			Global.OnProcess?.Invoke("The API Gateway Controller is starting");
			Global.OnProcess?.Invoke($"Version: {Assembly.GetCallingAssembly().GetVersion()}");
#if DEBUG
			Global.OnProcess?.Invoke($"Working mode: {(this.IsUserInteractive ? "Interactive app" : "Background service")} (DEBUG)");
#else
			Global.OnProcess?.Invoke($"Working mode: {(this.IsUserInteractive ? "Interactive app" : "Background service")} (RELEASE)");
#endif
			Global.OnProcess?.Invoke($"Starting arguments: {(args != null && args.Length > 0 ? args.Join(" ") : "None")}");
			Global.OnProcess?.Invoke($"Environment:\r\n\t{Extensions.GetRuntimeEnvironment()}");
			Global.OnProcess?.Invoke($"API Gateway Router: {new Uri(Router.GetRouterStrInfo()).GetResolvedURI()}");
			Global.OnProcess?.Invoke($"Working directory: {this.WorkingDirectory}");
			Global.OnProcess?.Invoke($"Temporary directory: {UtilityService.GetAppSetting("Path:Temp", "None")}");
			Global.OnProcess?.Invoke($"Static files directory: {UtilityService.GetAppSetting("Path:Statics", "None")}");
			Global.OnProcess?.Invoke($"Status files directory: {UtilityService.GetAppSetting("Path:Status", "None")}");
			Global.OnProcess?.Invoke($"Number of business services: {(!this.AllowRegisterBusinessServices ? "None" : $"{this.BusinessServices.Count}")}");
			Global.OnProcess?.Invoke($"Number of scheduling tasks: {(!this.AllowRegisterHelperTimers ? "None" : $"{this.Tasks.Count}")}");

			// prepare database settings
			this.PrepareDatabaseSettings();

			// generate new encryption keys
			if (args?.FirstOrDefault(arg => arg.IsStartsWith("/generate-keys")) != null)
			{
				var directoryPath = Global.GetPath("Path:Temp", "temp", false);
				if (Directory.Exists(directoryPath))
				{
					var keys = new List<string>();
					for (var counter = 0; counter < 10; counter++)
					{
						using (var rsa = System.Security.Cryptography.RSA.Create())
						{
							rsa.KeySize = 2048;
							keys.Add("RSA: " + rsa.ExportJsonParameters(true).Encrypt());
						}
						keys.Add("ECC: " + CryptoService.GenerateRandomKey().Encrypt().ToBase64());
						keys.Add("Keys (hex):");
						keys.Add("- 512 bits: " + CryptoService.GenerateRandomKey(512).ToHex());
						keys.Add("- 384 bits: " + CryptoService.GenerateRandomKey(384).ToHex());
						keys.Add("- 256 bits: " + CryptoService.GenerateRandomKey(256).ToHex());
						keys.Add("- 128 bits: " + CryptoService.GenerateRandomKey(128).ToHex());
						keys.Add("-----------------------------------------------------------------------");
					}
					var filePath = Path.Combine(directoryPath, "@keys.txt");
					Global.OnProcess?.Invoke($"New encryption keys were generated => {filePath}");
					keys.SaveTo(filePath, false);
				}
			}

			// connect to API Gateway Router
			var attemptingCounter = 0;

			void connectRouter()
				=> connectRouterAsync().Execute(true);

			async Task connectRouterAsync()
			{
				attemptingCounter++;
				Global.OnProcess?.Invoke($"Attempting to connect to API Gateway Router [{new Uri(Router.GetRouterStrInfo()).GetResolvedURI()}] #{attemptingCounter}");
				try
				{
					await Router.ConnectAsync
					(
						async (sender, arguments) =>
						{
							Global.OnProcess?.Invoke($"The API Gateway incoming channel was established - Session ID: {arguments.SessionId}");
							await Router.IncomingChannel.UpdateAsync(Router.IncomingChannelSessionID, "APIGateway", $"Incoming: services.controllers @ {this.Info.ID}").ConfigureAwait(false);
							if (this.State == ServiceState.Initializing)
								this.State = ServiceState.Ready;

							this.InterCommunicator?.Dispose();
							this.InterCommunicator = Router.IncomingChannel.Subscribe<CommunicateMessage>
							(
								"messages.services.apigateway",
								message => this.Info.ID.IsEquals(message.ExcludedNodeID) ? Task.CompletedTask : this.ProcessInterCommunicateMessageAsync(message),
								exception => Global.OnError?.Invoke($"Error occurred while fetching an inter-communicate message of API Gateway => {exception.Message}", this.State == ServiceState.Connected ? exception : null)
							);
							Global.OnProcess?.Invoke($"The communicator of API Gateway was{(this.State == ServiceState.Disconnected ? " re-" : " ")}subscribed successful");

							this.UpdateCommunicator?.Dispose();
							this.UpdateCommunicator = Router.IncomingChannel.Subscribe<UpdateMessage>
							(
								"messages.update",
								message =>
								{
									if (message.Type.IsEquals("Ping"))
										this.ClientPingTime = DateTime.Now;
									else if (message.Type.IsEquals("Scheduler"))
										this.ClientSchedulingTime = DateTime.Now;
								},
								exception => Global.OnError?.Invoke($"Error occurred while fetching an updating message => {exception.Message}", this.State == ServiceState.Connected ? exception : null)
							);
							Global.OnProcess?.Invoke($"The updater of service messages was{(this.State == ServiceState.Disconnected ? " re-" : " ")}subscribed successful");

							try
							{
								await this.RegisterHelperServicesAsync().ConfigureAwait(false);
							}
							catch
							{
								try
								{
									await Task.Delay(UtilityService.GetRandomNumber(456, 789), this.CancellationToken).ConfigureAwait(false);
									await this.RegisterHelperServicesAsync().ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									Global.OnError?.Invoke($"Error occurred while{(this.State == ServiceState.Disconnected ? " re-" : " ")}registering the helper services => {ex.Message}", ex);
								}
							}

							if (this.State == ServiceState.Ready)
							{
								// helper services
								if (this.AllowRegisterHelperTimers)
									try
									{
										this.RegisterTimers();
										Global.OnProcess?.Invoke($"The background workers & schedulers are registered - Number of scheduling timers: {this.NumberOfTimers:#,##0} - Number of scheduling tasks: {this.NumberOfTasks:#,##0}");
									}
									catch (Exception ex)
									{
										Global.OnError?.Invoke($"Error occurred while registering background workers & schedulers => {ex.Message}", ex);
									}

								// business services
								if (this.AllowRegisterBusinessServices)
								{
									this.BusinessServices.ForEach(kvp => this.StartBusinessService(kvp.Key), true);
									this.StartTimer(() => this.WatchBusinessServices(), 5);
								}
							}

							try
							{
								onIncomingConnectionEstablished?.Invoke(sender, arguments);
							}
							catch (Exception ex)
							{
								Global.OnError?.Invoke($"Error occurred while invoking \"{nameof(onIncomingConnectionEstablished)}\" => {ex.Message}", ex);
							}

							if (this.State == ServiceState.Ready)
								try
								{
									next?.Invoke(this);
								}
								catch (Exception ex)
								{
									Global.OnError?.Invoke($"Error occurred while invoking the next action => {ex.Message}", ex);
								}

							stopwatch.Stop();
							Global.OnProcess?.Invoke($"The API Gateway Controller was{(this.State == ServiceState.Disconnected ? " re-" : " ")}started - PID: {Process.GetCurrentProcess().Id} - Execution times: {stopwatch.GetElapsedTimes()}");
							this.State = ServiceState.Connected;

							while (Router.IncomingChannel == null || Router.OutgoingChannel == null)
								await Task.Delay(UtilityService.GetRandomNumber(123, 456), this.CancellationToken).ConfigureAwait(false);

							if (this.AllowRegisterBusinessServices || this.AllowRegisterHelperServices || this.AllowRegisterHelperTimers)
								await this.SendInterCommunicateMessageAsync("Controller#Info", this.Info.ToJson(), this.CancellationToken).ConfigureAwait(false);

							await Task.Delay(UtilityService.GetRandomNumber(4567, 5678), this.CancellationToken).ConfigureAwait(false);
							await Task.WhenAll
							(
								this.SendInterCommunicateMessageAsync("Controller#RequestInfo", null, this.CancellationToken),
								this.SendInterCommunicateMessageAsync("Service#RequestInfo", null, this.CancellationToken)
							).ConfigureAwait(false);
						},
						(sender, arguments) =>
						{
							if (this.State == ServiceState.Connected)
							{
								stopwatch.Restart();
								this.State = ServiceState.Disconnected;
							}
							var closeMode = Router.ChannelsAreClosedBySystem || (arguments.CloseType.Equals(SessionCloseType.Goodbye) && "wamp.close.normal".IsEquals(arguments.Reason)) ? "closed" : "broken";
							Global.OnProcess?.Invoke($"The API Gateway incoming channel was {closeMode} - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
						},
						(sender, arguments) => Global.OnError?.Invoke($"Got an unexpected error of the API Gateway incoming channel => {arguments.Exception?.Message}", arguments.Exception),
						async (sender, arguments) =>
						{
							Global.OnProcess?.Invoke($"The API Gateway outgoing channel was established - Session ID: {arguments.SessionId}");
							await Router.OutgoingChannel.UpdateAsync(Router.OutgoingChannelSessionID, "APIGateway", $"Outgoing: services.controllers @ {this.Info.ID}").ConfigureAwait(false);

							try
							{
								while (Router.IncomingChannel == null)
									await Task.Delay(UtilityService.GetRandomNumber(123, 456), this.CancellationToken).ConfigureAwait(false);
								onOutgoingConnectionEstablished?.Invoke(sender, arguments);
							}
							catch (Exception ex)
							{
								Global.OnError?.Invoke($"Error occurred while invoking \"{nameof(onOutgoingConnectionEstablished)}\" => {ex.Message}", ex);
							}
						},
						(sender, arguments) =>
						{
							var closeMode = Router.ChannelsAreClosedBySystem || (arguments.CloseType.Equals(SessionCloseType.Goodbye) && "wamp.close.normal".IsEquals(arguments.Reason)) ? "closed" : "broken";
							Global.OnProcess?.Invoke($"The API Gateway outgoing channel was {closeMode} - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
						},
						(sender, arguments) => Global.OnError?.Invoke($"Got an unexpected error of the API Gateway outgoing channel => {arguments.Exception?.Message}", arguments.Exception),
						this.CancellationToken
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while connecting to API Gateway Router => {ex.Message}", ex);
					if (attemptingCounter < 13)
					{
						await Task.Delay(UtilityService.GetRandomNumber(456, 789), this.CancellationToken).ConfigureAwait(false);
						UtilityService.ExecuteTask(connectRouter).Execute();
					}
					else
						Global.OnError?.Invoke($"Don't attempt to connect to API Gateway Router after {attemptingCounter} tried times => need to check API Gateway Router", null);
				}
			}

			connectRouter();

			if (this.AllowRegisterHelperServices)
			{
				// flush logs
				if (args?.FirstOrDefault(arg => arg.IsStartsWith("/no-log-flusher")) == null)
				{
					this.StartTimer(() =>
					{
						if (this.LogFlusher == null)
							this.StartLogFlusher("/do-sync-work /flush");
					}, this.FlushingInterval);
					this.StartTimer(() =>
					{
						if ((DateTime.Now - this.LogFlusherTime).TotalMinutes > 10)
							ExternalProcess.Kill(this.LogFlusher?.Process);
					}, 60);
				}

				// warm-up/refresh HTTP services
				var urls = this.HttpServices.Select(name => UtilityService.GetAppSetting($"HttpUri:{name}")).Where(url => !string.IsNullOrWhiteSpace(url) && (url.IsStartsWith("https://") || url.IsStartsWith("http://"))).Select(url => url + UtilityService.GetAppSetting("LoadBalancer:RefreshURL", "/favicon.ico?t={iso-time-miliseconds}&n={node-id}")).ToList();
				if (!Int32.TryParse(UtilityService.GetAppSetting("LoadBalancer:Nodes", "0"), out var nodes) || nodes < 1)
					nodes = 1;

				if (urls.Count > 0)
				{
					Task warmUpAsync()
						=> urls.ForEachAsync(async url =>
						{
							for (var index = 0; index < nodes; index++)
								try
								{
									using (var request = await new Uri(this.PrepareTimestamps(url)).SendHttpRequestAsync().ConfigureAwait(false))
										await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
								}
								catch { }
						});
					warmUpAsync().Execute();
					this.StartTimer(warmUpAsync, this.FlushingInterval * this.FlushingInterval);
				}
			}
		}

		/// <summary>
		/// Stops the API Gateway Controller
		/// </summary>
		/// <returns></returns>
		public async Task StopAsync()
		{
			// stop all external processes (services & tasks)
			if (this.AllowRegisterBusinessServices || this.Tasks.Count > 0)
				try
				{
					await Task.WhenAll
					(
						this.BusinessServices.Keys.ForEachAsync(name => UtilityService.ExecuteTask(() => this.StopBusinessService(name, false, false))),
						this.Tasks.Values.ForEachAsync(serviceInfo => UtilityService.ExecuteTask(() => ExternalProcess.Stop(serviceInfo.Instance, null, null, 789)))
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while disposing external processes (services & tasks) => {ex.Message}", ex);
				}

			// dispose all timers
			try
			{
				this.Timers.ForEach(timer => timer?.Dispose(), true);
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Error occurred while disposing the controllers' timers => {ex.Message}", ex);
			}

			// send info to other managers
			if (this.AllowRegisterBusinessServices || this.AllowRegisterHelperServices || this.AllowRegisterHelperTimers)
				try
				{
					this.Info.Available = false;
					await this.SendInterCommunicateMessageAsync("Controller#Disconnect", this.Info.ToJson(), this.CancellationToken).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Cannot send the updating information => {ex.Message}", ex);
				}

			// dipose all helper services
			if (this.ManagingService != null)
				try
				{
					await this.ManagingService.DisposeAsync().ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Cannot dispose the managing service => {ex.Message}", ex);
				}
				finally
				{
					this.ManagingService = null;
				}

			if (this.AllowRegisterHelperServices)
			{
				this.StopLogFlusher();
				if (this.MessagingService != null)
					try
					{
						await this.MessagingService.DisposeAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke($"Cannot dispose the messaging service => {ex.Message}", ex);
					}
					finally
					{
						this.MessagingService = null;
					}
			}

			// do clean-up tasks
			try
			{
				this.MailSender?.Dispose();
				await MailSender.SaveMessagesAsync().ConfigureAwait(false);

				this.WebHookSender?.Dispose();
				await WebHookSender.SaveMessagesAsync().ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Error occurred while cleaning-up the controller => {ex.Message}", ex);
			}

			// disconnect from API Gateway Router
			try
			{
				this.InterCommunicator?.Dispose();
				this.UpdateCommunicator?.Dispose();
				this.CancellationTokenSource.Cancel();
				await Router.DisconnectAsync().ConfigureAwait(false);
				this.State = ServiceState.Disconnected;
				Global.OnProcess?.Invoke($"The API Gateway Controller was disconnected");
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Error occurred while disconnecting the controller => {ex.Message}", ex);
			}

			// final
			Global.OnProcess?.Invoke($"The API Gateway Controller was stopped");
		}

		/// <summary>
		/// Stops the API Gateway Controller
		/// </summary>
		public void Stop()
			=> this.StopAsync().Execute(true);

		void PrepareDatabaseSettings()
		{
			Global.OnProcess?.Invoke($"Prepare database settings with additional configuration of [{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}]");

			var connectionStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			var dbProviderFactories = new Dictionary<string, XmlNode>(StringComparer.OrdinalIgnoreCase);
			var dataSources = new Dictionary<string, XmlNode>(StringComparer.OrdinalIgnoreCase);

			var dbprovidersSection = UtilityService.GetAppSetting("Section:DbProviders", "net.vieapps.dbproviders");
			var repositoriesSection = UtilityService.GetAppSetting("Section:Repositories", "net.vieapps.repositories");

			// settings of controllers
			if (ConfigurationManager.ConnectionStrings != null && ConfigurationManager.ConnectionStrings.Count > 0)
				for (var index = 0; index < ConfigurationManager.ConnectionStrings.Count; index++)
				{
					var connectionString = ConfigurationManager.ConnectionStrings[index];
					if (!connectionStrings.ContainsKey(connectionString.Name))
						connectionStrings[connectionString.Name] = connectionString.ConnectionString;
				}

			if (!(ConfigurationManager.GetSection(dbprovidersSection) is AppConfigurationSectionHandler dbProvidersConfiguration))
				dbProvidersConfiguration = ConfigurationManager.GetSection("dbProviderFactories") as AppConfigurationSectionHandler;
			dbProvidersConfiguration?.Section.SelectNodes("./add").ToList().ForEach(dbProviderNode =>
			{
				var invariant = dbProviderNode.Attributes["invariant"]?.Value ?? dbProviderNode.Attributes["name"]?.Value;
				if (!string.IsNullOrWhiteSpace(invariant) && !dbProviderFactories.ContainsKey(invariant))
					dbProviderFactories[invariant] = dbProviderNode;
			});

			if (ConfigurationManager.GetSection(repositoriesSection) is AppConfigurationSectionHandler repositoriesConfiguration)
			{
				repositoriesConfiguration.Section.SelectNodes("./dataSources/dataSource").ToList().ForEach(dataSourceNode =>
				{
					var dataSourceName = dataSourceNode.Attributes["name"]?.Value;
					if (!string.IsNullOrWhiteSpace(dataSourceName) && !dataSources.ContainsKey(dataSourceName))
					{
						var connectionStringName = dataSourceNode.Attributes["connectionStringName"]?.Value;
						if (!string.IsNullOrWhiteSpace(connectionStringName) && connectionStrings.TryGetValue(connectionStringName, out var connectionString))
						{
							var attribute = dataSourceNode.OwnerDocument.CreateAttribute("connectionString");
							attribute.Value = connectionString;
							dataSourceNode.Attributes.Append(attribute);
							dataSources[dataSourceName] = dataSourceNode;
						}
					}
				});

				var name = repositoriesConfiguration.Section.Attributes["versionDataSource"]?.Value;
				if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.VersionDataSources.IndexOf(name) < 0)
					this.VersionDataSources.Add(name);

				name = repositoriesConfiguration.Section.Attributes["trashDataSource"]?.Value;
				if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.TrashDataSources.IndexOf(name) < 0)
					this.TrashDataSources.Add(name);

				if (repositoriesConfiguration.Section.SelectNodes("./repository") is XmlNodeList repositoryNodes)
					repositoryNodes.ToList().ForEach(repository =>
					{
						name = repository.Attributes["versionDataSource"]?.Value;
						if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.TrashDataSources.IndexOf(name) < 0)
							this.TrashDataSources.Add(name);

						name = repository.Attributes["trashDataSource"]?.Value;
						if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.TrashDataSources.IndexOf(name) < 0)
							this.TrashDataSources.Add(name);
					});
			}

			// settings of services
			new[]
			{
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.exe.config",
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.dll.config"
			}.Where(filename => File.Exists(filename)).ForEach(filename =>
			{
				var xml = new FileInfo(filename).ReadAsXml();

				if (xml.DocumentElement.SelectNodes("/configuration/connectionStrings/add") is XmlNodeList connectionStringNodes)
					connectionStringNodes.ToList().ForEach(connectionStringNode =>
					{
						var name = connectionStringNode.Attributes["name"]?.Value;
						var connectionString = connectionStringNode.Attributes["connectionString"]?.Value;
						if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(connectionString) && !connectionStrings.ContainsKey(name))
							connectionStrings[name] = connectionString;
					});

				if (!(xml.DocumentElement.SelectNodes($"/configuration/{dbprovidersSection}/add") is XmlNodeList dbProviderNodes))
					dbProviderNodes = xml.DocumentElement.SelectNodes("/configuration/dbProviderFactories/add");
				dbProviderNodes?.ToList().ForEach(dbProviderNode =>
				{
					var invariant = dbProviderNode.Attributes["invariant"]?.Value ?? dbProviderNode.Attributes["name"]?.Value;
					if (!string.IsNullOrWhiteSpace(invariant) && !dbProviderFactories.ContainsKey(invariant))
						dbProviderFactories[invariant] = dbProviderNode;
				});

				if (xml.DocumentElement.SelectSingleNode($"/configuration/{repositoriesSection}") is XmlNode repositoriesConfig)
				{
					if (repositoriesConfig.SelectNodes("./dataSources/dataSource") is XmlNodeList dataSourceNodes)
						dataSourceNodes.ToList().ForEach(dataSourceNode =>
						{
							var dataSourceName = dataSourceNode.Attributes["name"]?.Value;
							if (!string.IsNullOrWhiteSpace(dataSourceName) && !dataSources.ContainsKey(dataSourceName))
							{
								var connectionStringName = dataSourceNode.Attributes["connectionStringName"]?.Value;
								if (!string.IsNullOrWhiteSpace(connectionStringName) && connectionStrings.TryGetValue(connectionStringName, out var connectionString))
								{
									var attribute = xml.CreateAttribute("connectionString");
									attribute.Value = connectionString;
									dataSourceNode.Attributes.Append(attribute);
									dataSources[dataSourceName] = dataSourceNode;
								}
							}
						});

					var name = repositoriesConfig.Attributes["versionDataSource"]?.Value;
					if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.VersionDataSources.IndexOf(name) < 0)
						this.VersionDataSources.Add(name);

					name = repositoriesConfig.Attributes["trashDataSource"]?.Value;
					if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.TrashDataSources.IndexOf(name) < 0)
						this.TrashDataSources.Add(name);

					if (repositoriesConfig.SelectNodes("./repository") is XmlNodeList repositoryNodes)
						repositoryNodes.ToList().ForEach(repository =>
						{
							name = repository.Attributes["versionDataSource"]?.Value;
							if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.TrashDataSources.IndexOf(name) < 0)
								this.TrashDataSources.Add(name);

							name = repository.Attributes["trashDataSource"]?.Value;
							if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.TrashDataSources.IndexOf(name) < 0)
								this.TrashDataSources.Add(name);
						});
				}
			});

			Global.OnProcess?.Invoke($"Construct {dbProviderFactories.Count:#,##0} SQL Provider(s)");
			RepositoryStarter.ConstructDbProviderFactories(dbProviderFactories.Values.ToList(), (msg, ex) =>
			{
				if (ex != null)
					Global.OnError?.Invoke(msg, ex);
				else
					Global.OnProcess?.Invoke(msg);
			});

			Global.OnProcess?.Invoke($"Construct {dataSources.Count:#,##0} data source(s) with {connectionStrings.Count:#,##0} connection string(s): {connectionStrings.ToString(", ", kvp => kvp.Key)}");
			RepositoryStarter.ConstructDataSources(dataSources.Values.ToList(), (msg, ex) =>
			{
				if (ex != null)
					Global.OnError?.Invoke(msg, ex);
				else
					Global.OnProcess?.Invoke(msg);
			});

			Global.OnProcess?.Invoke($"{this.VersionDataSources.Count:#,##0} data source(s) of version content: {this.VersionDataSources.Join(", ")}");
			Global.OnProcess?.Invoke($"{this.TrashDataSources.Count:#,##0} data source(s) of trash content: {this.TrashDataSources.Join(", ")}");
		}
		#endregion

		#region Start/Stop business service
		/// <summary>
		/// Gets the process information of a business service
		/// </summary>
		/// <param name="name">The name of a service</param>
		/// <returns></returns>
		public ProcessInfo GetServiceProcessInfo(string name)
			=> !string.IsNullOrWhiteSpace(name) && this.BusinessServices.TryGetValue(name.ToArray('.').Last().ToLower(), out var processInfo) ? processInfo : null;

		/// <summary>
		/// Gets the collection of available businness services
		/// </summary>
		public Dictionary<string, ProcessInfo> AvailableBusinessServices
			=> this.BusinessServices.Where(kvp => this.IsBusinessServiceAvailable(kvp.Key)).ToDictionary();

		/// <summary>
		/// Gets the collection of available businness services
		/// </summary>
		/// <returns></returns>
		public Dictionary<string, string> GetAvailableBusinessServices()
			=> this.AvailableBusinessServices.ToDictionary(kvp => $"services.{kvp.Key}", kvp => kvp.Value.Arguments);

		/// <summary>
		/// Gets the state that determines a business service is available or not
		/// </summary>
		/// <param name="name">The name of a service</param>
		/// <returns></returns>
		public bool IsBusinessServiceAvailable(string name)
		{
			var processInfo = this.GetServiceProcessInfo(name);
			return processInfo != null && processInfo.Get<string>("NotAvailable") == null;
		}

		/// <summary>
		/// Gets the state that determines a business service is running or not
		/// </summary>
		/// <param name="name">The name of a service</param>
		/// <returns></returns>
		public bool IsBusinessServiceRunning(string name)
		{
			var processInfo = this.GetServiceProcessInfo(name);
			return processInfo != null && processInfo.Instance != null && "Running".IsEquals(processInfo.Get<string>("State"));
		}

		/// <summary>
		/// Gets the arguments for starting a business service with environment information
		/// </summary>
		/// <returns></returns>
		public string GetServiceArguments()
		{
			var runtimeArguments = Extensions.GetRuntimeArguments();
			return $"/user:{runtimeArguments.User.UrlEncode()} /host:{runtimeArguments.Host.UrlEncode()} /platform:{runtimeArguments.Platform.UrlEncode()} /os:{runtimeArguments.OS.UrlEncode()}";
		}

		/// <summary>
		/// Starts a business service
		/// </summary>
		/// <param name="name">The name of a service</param>
		/// <param name="arguments">The starting arguments</param>
		public void StartBusinessService(string name, string arguments = null)
		{
			if (!this.IsBusinessServiceAvailable(name))
			{
				var ex = new ServiceNotFoundException($"The service [{name ?? "unknown"}] is not found");
				Global.OnError?.Invoke($"[{name ?? "unknown"}] => {ex.Message}", ex);
				return;
			}

			name = name.ToArray('.').Last().ToLower();
			if (this.IsBusinessServiceRunning(name))
				return;

			var re = "Running".IsEquals(this.BusinessServices[name].Get<string>("State")) ? "re-" : "";
			Global.OnProcess?.Invoke($"[{name}] => The service is {re}starting");

			try
			{
				var serviceHosting = string.IsNullOrWhiteSpace(this.BusinessServices[name].Executable) ? this.ServiceHosting : this.BusinessServices[name].Executable;
				if (!File.Exists(serviceHosting + (this.IsWindows ? ".exe" : "")))
					throw new FileNotFoundException($"The service hosting is not found [{serviceHosting + (this.IsWindows ? ".exe" : "")}]");

				this.BusinessServices[name].Instance = ExternalProcess.Start
				(
					serviceHosting,
					$"/svc:{this.BusinessServices[name].Arguments} {arguments ?? ""} /agc:r {this.GetServiceArguments().Replace("/", "/call-")} /controller-id:{this.Info.ID}".Trim(),
					(sender, args) =>
					{
						this.BusinessServices[name].Instance = null;
						Global.OnServiceStopped?.Invoke(name, $"The service was stopped{("Error".IsEquals(this.BusinessServices[name].Get<string>("State")) ? $" ({this.BusinessServices[name].Get<string>("Error")})" : "")}");
					},
					(sender, args) =>
					{
						if (!string.IsNullOrWhiteSpace(args.Data))
						{
							Global.OnGotServiceMessage?.Invoke(name, args.Data);
							if (args.Data.IsStartsWith("Error: The service component") || args.Data.IsContains("Could not load file or assembly"))
								this.BusinessServices[name].Set(new Dictionary<string, string>
								{
									{ "State", "Error" },
									{ "Error", args.Data },
									{ "NotAvailable", "" }
								});
						}
					}
				);

				this.BusinessServices[name].Set("State", "Running");
				Global.OnServiceStarted?.Invoke(name, $"The service was {re}started{(this.BusinessServices[name].RecycleAt != null ? $" (be recycled at {this.BusinessServices[name].RecycleAt.Value:HH:mm:ss})" : "")} - Process ID: {this.BusinessServices[name].Instance.ID}");
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"[{name}] => Cannot {re}start the service: {ex.Message}", ex is FileNotFoundException ? null : ex);
				this.BusinessServices[name].Set(new Dictionary<string, string>
				{
					{ "State", "Error" },
					{ "Error", ex.Message },
					{ "ErrorStack", ex.StackTrace }
				});
			}
		}

		/// <summary>
		/// Stops a business service
		/// </summary>
		/// <param name="name">The name of a service</param>
		/// <param name="available">The available state</param>
		/// <param name="sendServiceInfo">true to send service information to API Gateway</param>
		public void StopBusinessService(string name, bool available, bool sendServiceInfo = true)
		{
			name = !string.IsNullOrWhiteSpace(name) ? name.ToArray('.').Last().ToLower() : "unknown";
			if (!this.BusinessServices.ContainsKey(name))
			{
				var ex = new ServiceNotFoundException($"The service [{name}] is not found");
				Global.OnError?.Invoke($"[{name}] => {ex.Message}", ex);
				return;
			}

			var processInfo = this.GetServiceProcessInfo(name);
			if (processInfo == null || processInfo.Instance == null)
				return;

			Global.OnProcess?.Invoke($"[{name}] => The service is stopping");
			if (this.IsWindows)
				try
				{
					var info = ExternalProcess.Start(processInfo.Instance.FilePath, processInfo.Instance.Arguments.Replace("/agc:r", "/agc:s"), "");
					using (info.Process)
						this.BusinessServices[name].Set("State", "Stopped");
					if (sendServiceInfo)
						this.SendServiceInfo(name, processInfo.Instance?.Arguments, available, false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while stopping the service [{name}] => {ex.Message}", ex);
					this.BusinessServices[name].Set(new Dictionary<string, string>
					{
						{ "State", "Error" },
						{ "Error", ex.Message },
						{ "ErrorStack", ex.StackTrace }
					});
					if (sendServiceInfo)
						this.SendServiceInfo(name, processInfo.Instance?.Arguments, false, false);
				}
			else
				ExternalProcess.Stop
				(
					processInfo.Instance,
					info =>
					{
						this.BusinessServices[name].Set("State", "Stopped");
						if (sendServiceInfo)
							this.SendServiceInfo(name, processInfo.Instance?.Arguments, available, false);
					},
					ex =>
					{
						Global.OnError?.Invoke($"Error occurred while stopping the service [{name}] => {ex.Message}", ex);
						this.BusinessServices[name].Set(new Dictionary<string, string>
						{
							{ "State", "Error" },
							{ "Error", ex.Message },
							{ "ErrorStack", ex.StackTrace }
						});
						if (sendServiceInfo)
							this.SendServiceInfo(name, processInfo.Instance?.Arguments, false, false);
					},
					1234
				);
		}

		/// <summary>
		/// Stops a business service
		/// </summary>
		/// <param name="name">The name of a service</param>
		public void StopBusinessService(string name)
			=> this.StopBusinessService(name, true);

		void WatchBusinessServices()
		{
			var svcArgs = this.GetServiceArguments().Replace("/", "/call-");
			this.BusinessServices.ForEach(kvp =>
			{
				var svcInfo = kvp.Value;
				if (svcInfo.Instance != null && svcInfo.RecycleAt != null && DateTime.Now >= svcInfo.RecycleAt.Value && DateTime.Now <= svcInfo.RecycleAt.Value.AddSeconds(5))
					ExternalProcess.Kill(svcInfo.Instance.Process, null, _ =>
					{
						using (svcInfo.Instance.Process)
							this.BusinessServices[kvp.Key].Set("State", "Running");
						svcInfo.Instance = null;
						svcInfo.RecycleAt = DateTime.Parse($"{DateTime.Now.AddDays(1):yyyy/MM/dd} {svcInfo.RecycleAt.Value:HH:mm:ss}");
						Global.OnProcess?.Invoke($"The service [{kvp.Key}] was killed (be recycled at {svcInfo.RecycleAt.Value:HH:mm:ss})");
					});
				else if (svcInfo.Instance == null && "Running".IsEquals(svcInfo.Get<string>("State")))
					this.StartBusinessService(kvp.Key, svcArgs);
			});
		}
		#endregion

		#region Register helper services
		async Task RegisterHelperServicesAsync()
		{
			try
			{
				if (this.ManagingService != null)
					await this.ManagingService.DisposeAsync().ConfigureAwait(false);
			}
			catch { }
			try
			{
				this.ManagingService = await Router.IncomingChannel.RegisterAsync<IController>(() => this, RegistrationInterceptor.Create(this.Info.ID, WampInvokePolicy.Single)).ConfigureAwait(false);
				Global.OnProcess?.Invoke($"The managing service was{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");
			}
			catch (WampSessionNotEstablishedException)
			{
				throw;
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Error occurred while{(this.State == ServiceState.Disconnected ? " re-" : " ")}registering the managing service => {ex.Message}", ex);
			}

			try
			{
				if (this.MessagingService != null)
					await this.MessagingService.DisposeAsync().ConfigureAwait(false);
			}
			catch { }
			if (this.AllowRegisterHelperServices)
				try
				{
					this.MessagingService = await Router.IncomingChannel.RegisterAsync<IMessagingService>(() => new MessagingService(), RegistrationInterceptor.Create()).ConfigureAwait(false);
					Global.OnProcess?.Invoke($"The messaging service was{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");
				}
				catch (WampSessionNotEstablishedException)
				{
					throw;
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while{(this.State == ServiceState.Disconnected ? " re-" : " ")}registering the messaging service => {ex.Message}", ex);
				}
		}

		void StartLogFlusher(string arguments = null)
		{
			if (string.IsNullOrWhiteSpace(this.ServiceHosting) || !File.Exists($"{this.ServiceHosting}{(this.IsWindows ? ".exe" : "")}"))
				Global.OnError?.Invoke($"Cannot start logging service. The hosting [{this.ServiceHosting}{(this.IsWindows ? ".exe" : "")}] is not found", null);

			else
				try
				{
					var svcComponent = UtilityService.GetAppSetting("Logs:Service:Component", "net.vieapps.Services.Logs.ServiceComponent,VIEApps.Services.Logs");
					var svcArguments = $"/svc:{svcComponent} {UtilityService.GetAppSetting("Logs:Service:Arguments", "")} {arguments ?? ""} /agc:r {this.GetServiceArguments().Replace("/", "/call-")} /controller-id:{this.Info.ID}".Trim();
					this.LogFlusher = ExternalProcess.Start(this.ServiceHosting, svcArguments, (_, __) =>
					{
						if (string.IsNullOrWhiteSpace(arguments))
							Global.OnProcess?.Invoke("The logging service was stopped");
						this.LogFlusher = null;
					}, null);
					if (!string.IsNullOrWhiteSpace(arguments))
					{
						Global.OnProcess?.Invoke("The logging service was started");
						this.LogFlusherTime = DateTime.Now;
					}
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while starting the logging service => {ex.Message}", ex);
				}
		}

		void StopLogFlusher()
		{
			if (this.LogFlusher != null)
			{
				if (this.IsWindows)
					try
					{
						ExternalProcess.Start(this.LogFlusher.FilePath, this.LogFlusher.Arguments.Replace("/agc:r", "/agc:s"), "").Process.Dispose();
						Global.OnProcess?.Invoke("The logging service was stopped");
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke($"Error occurred while stopping the logging service => {ex.Message}", ex);
						ExternalProcess.Kill(this.LogFlusher?.Process);
					}
					finally
					{
						this.LogFlusher = null;
					}
				else
					ExternalProcess.Stop
					(
						this.LogFlusher,
						_ =>
						{
							Global.OnProcess?.Invoke($"The logging service was stopped");
							this.LogFlusher = null;
						},
						ex =>
						{
							Global.OnError?.Invoke($"Error occurred while stopping the logging service => {ex.Message}", ex);
							ExternalProcess.Kill(this.LogFlusher?.Process);
							this.LogFlusher = null;
						},
						1234
					);
			}
		}
		#endregion

		#region Register timers for working with background workers & schedulers
		IDisposable StartTimer(Action action, int interval, int delay = 0)
		{
			interval = interval < 1 ? 1 : interval;
			var timer = Observable.Timer(TimeSpan.FromMilliseconds(delay > 0 ? delay : interval * 1000), TimeSpan.FromSeconds(interval)).Subscribe(_ =>
			{
				try
				{
					action();
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while running a timer => {ex.Message}", ex);
				}
			});
			this.Timers.Add(timer);
			return timer;
		}

		IDisposable StartTimer(Func<Task> action, int interval, int delay = 0)
		{
			interval = interval < 1 ? 1 : interval;
			var timer = Observable.Timer(TimeSpan.FromMilliseconds(delay > 0 ? delay : interval * 1000), TimeSpan.FromSeconds(interval)).Subscribe(async _ =>
			{
				try
				{
					await action().ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while running a timer => {ex.Message}", ex);
				}
			});
			this.Timers.Add(timer);
			return timer;
		}

		void RegisterTimers()
		{
			// send email messages
			this.StartTimer(async () =>
			{
				if (this.MailSender == null)
					try
					{
						this.MailSender = new MailSender(this.CancellationToken);
						await this.MailSender.ProcessAsync
						(
							message =>
							{
								var log = "The email message has been sent" + "\r\n" +
									$"- ID: {message.ID}" + "\r\n" +
									$"- From: {message.From}" + "\r\n" +
									$"- To: {message.To}" + (!string.IsNullOrWhiteSpace(message.Cc) ? $" / {message.Cc}" : "") + (!string.IsNullOrWhiteSpace(message.Bcc) ? $" / {message.Bcc}" : "") + "\r\n" +
									$"- Subject: {message.Subject}";
								Global.WriteLog(message.CorrelationID, "APIGateway", "Emails", log);
							},
							(message, exception, beRemoved) =>
							{
								var log = $"Error occurred while sending an email message => {exception.Message} [{exception.GetType()}]" + "\r\n" +
									$"- ID: {message.ID}" + "\r\n" +
									$"- From: {message.From}" + "\r\n" +
									$"- To: {message.To}" + (!string.IsNullOrWhiteSpace(message.Cc) ? $" / {message.Cc}" : "") + (!string.IsNullOrWhiteSpace(message.Bcc) ? $" / {message.Bcc}" : "") + "\r\n" +
									$"- Subject: {message.Subject}" +
									$"{(beRemoved ? "\r\n++ NOTED: The message will  be removed from queue because its failed too much times" : "")}";
								Global.WriteLog(message.CorrelationID, "APIGateway", "Emails", log, exception.StackTrace);
							}
						).ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke($"Error occurred while processing email messages: {ex.Message}", ex);
					}
					finally
					{
						this.MailSender?.Dispose();
						this.MailSender = null;
					}
			}, Int32.TryParse(UtilityService.GetAppSetting("TimerInterval:Mail", "5"), out var emailInterval) && emailInterval > 0 ? emailInterval : 5);

			// send web hook messages
			this.StartTimer(async () =>
			{
				if (this.WebHookSender == null)
					try
					{
						this.WebHookSender = new WebHookSender(this.CancellationToken);
						await this.WebHookSender.ProcessAsync
						(
							message =>
							{
								var log = "The web-hook message has been sent" + "\r\n" +
									$"- ID: {message.ID}" + "\r\n" +
									$"- End-point: {message.EndpointURL}";
								Global.WriteLog(message.CorrelationID, "APIGateway", "WebHooks", log);
							},
							(message, exception, beRemoved) =>
							{
								var log = $"Error occurred while sending a web-hook message => {exception.Message} [{exception.GetType()}]" + "\r\n" +
									$"- ID: {message.ID}" + "\r\n" +
									$"- End-point: {message.EndpointURL}" +
									$"{(beRemoved ? "\r\n++ NOTED: The message will  be removed from queue because its failed too much times" : "")}";
								Global.WriteLog(message.CorrelationID, "APIGateway", "WebHooks", log, exception.StackTrace);
							}
						).ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke($"Error occurred while processing web-hook messages: {ex.Message}", ex);
					}
					finally
					{
						this.WebHookSender?.Dispose();
						this.WebHookSender = null;
					}
			}, Int32.TryParse(UtilityService.GetAppSetting("TimerInterval:WebHook", "3"), out var webhookInterval) && webhookInterval > 0 ? webhookInterval : 3);

			// house keeper
			this.StartTimer(this.RunHouseKeeper, 60 * 60);
			this.StartTimer(() =>
			{
				var time = DateTime.Now.AddMinutes(-13);
				Directory.GetFiles(Global.LogsPath, "*.json")
					.Select(path => new FileInfo(path))
					.Where(file => file.LastWriteTime <= time)
					.ToList()
					.ForEach(file =>
					{
						try
						{
							file.Delete();
						}
						catch { }
					});
			}, 90);

			// task scheduler
			var runTaskSchedulerOnFirstLoad = false;
			if (ConfigurationManager.GetSection(UtilityService.GetAppSetting("Section:TaskScheduler", "net.vieapps.task.scheduler")) is AppConfigurationSectionHandler config)
				runTaskSchedulerOnFirstLoad = "true".IsEquals(config.Section.Attributes["runOnFirstLoad"]?.Value);
			this.StartTimer(this.RunTaskSchedulerAsync, 65 * 60, runTaskSchedulerOnFirstLoad ? 5678 : 0);

			// timers to send a signal to connected client devices
			if (this.IsTimers)
			{
				// ping
				this.StartTimer(() =>
				{
					if ((DateTime.Now - this.ClientPingTime).TotalSeconds >= this.PingInterval)
						new UpdateMessage
						{
							Type = "Ping",
							DeviceID = "*",
						}.Send();
				}, this.PingInterval + 13);

				// scheduler (update online status, signal to run scheduler at client, ...)
				this.StartTimer(() =>
				{
					if ((DateTime.Now - this.ClientSchedulingTime).TotalSeconds >= this.SchedulingInterval)
						new UpdateMessage
						{
							Type = "Scheduler",
							DeviceID = "*",
						}.Send();
				}, this.SchedulingInterval + 13);
			}
		}
		#endregion

		#region Run house keeper
		void RunHouseKeeper()
		{
			// stop if its still running
			if (this.IsHouseKeeperRunning)
				return;

			// prepare
			this.IsHouseKeeperRunning = true;
			var stopwatch = Stopwatch.StartNew();

			var paths = new HashSet<string>
			{
				Global.StatusPath,
				Global.TempPath,
				Global.LogsPath
			};
			paths.Append(UtilityService.GetAppSetting("HouseKeeper:Folders")?.ToHashSet('|') ?? new HashSet<string>());

			var excludedSubFolders = UtilityService.GetAppSetting("HouseKeeper:ExcludedSubFolders")?.ToList('|');
			var excludedFileExtensions = UtilityService.GetAppSetting("HouseKeeper:ExcludedFileExtensions")?.ToLower().ToHashSet('|') ?? new HashSet<string>();
			var remainHours = UtilityService.GetAppSetting("HouseKeeper:RemainHours", "24").CastAs<int>();
			var specialFolders = UtilityService.GetAppSetting("HouseKeeper:SpecialFolders")?.ToHashSet('|') ?? new HashSet<string>();
			var specialFileExtensions = UtilityService.GetAppSetting("HouseKeeper:SpecialFileExtensions")?.ToLower().ToHashSet('|') ?? new HashSet<string>();
			var specialRemainHours = UtilityService.GetAppSetting("HouseKeeper:SpecialRemainHours", "240").CastAs<int>();

			// process
			var remainTime = DateTime.Now.AddHours(0 - remainHours);
			var specialRemainTime = DateTime.Now.AddHours(0 - specialRemainHours);
			var counter = 0;
			paths.Select(path => new DirectoryInfo(path)).Where(dir => dir.Exists).ForEach(dir =>
			{
				// delete old files
				UtilityService.GetFiles(dir.FullName, "*.*", 0, true, excludedSubFolders)
					.Select(file => (File: file, Path: file.FullName.Left(file.FullName.Length - file.Name.Length - 1), file.Extension, file.LastWriteTime))
					.Where(info => !excludedFileExtensions.Contains(info.Extension) && info.LastWriteTime < (specialFileExtensions.Contains(info.Extension) || specialFolders.Select(specialPath => info.Path.IsStartsWith(specialPath)).Where(state => state).Any() ? specialRemainTime : remainTime))
					.Select(info => info.File)
					.ForEach(file =>
					{
						try
						{
							file.Delete();
							counter++;
						}
						catch { }
					});

				// delete empty folders
				dir.GetDirectories()
					.Select(sd => new[] { sd }.Concat(sd.GetDirectories()))
					.SelectMany(dirs => dirs)
					.Where(d => d != null && d.GetFiles().Length < 1 && d.GetDirectories().Length < 1)
					.ForEach(d =>
					{
						try
						{
							d.Delete(true);
						}
						catch { }
					});
			});

			// clean service logs
			remainTime = DateTime.Now.AddHours(-36);
			UtilityService.GetFiles(Global.LogsPath, "*.*")
				.Where(file => file.LastWriteTime < remainTime)
				.ForEach(file =>
				{
					try
					{
						file.Delete();
						counter++;
					}
					catch { }
				});

			new CommunicateMessage("Logs")
			{
				Type = "Clean"
			}.Send();

			// clean recycle-bin contents
			var logs = this.CleanRecycleBin();

			// clean trash
			var attachmentsPath = UtilityService.GetAppSetting("Path:Attachments");
			if (!string.IsNullOrWhiteSpace(attachmentsPath) && Directory.Exists(attachmentsPath))
			{
				remainTime = DateTime.Now.AddDays(-30);
				Directory.GetDirectories(attachmentsPath)
					.Where(path => path != null && path.Right(32).IsValidUUID())
					.Select(path => Path.Combine(path, "trash"))
					.Where(path => Directory.Exists(path))
					.ForEach(path =>
					{
						var files = UtilityService.GetFiles(path).Where(file => file.LastAccessTime < remainTime).ToList();
						if (files.Count > 0)
						{
							paths.Add(path);
							files.ForEach(file =>
							{
								try
								{
									file.Delete();
									counter++;
								}
								catch { }
							});
						}
					});
			}

			// done
			stopwatch.Stop();
			Global.OnProcess?.Invoke
			(
				"The house keeper is complete the working..." + "\r\n\r\nPaths\r\n=> " + paths.ToString("\r\n=> ") + "\r\n\r\n" +
				$"- Total of cleaned files: {counter:#,##0}" + "\r\n\r\n" +
				$"- Recycle-Bin\r\n\t" + logs.ToString("\r\n\t") + "\r\n\r\n" +
				$"- Execution times: {stopwatch.GetElapsedTimes()}"
			);
			this.IsHouseKeeperRunning = false;
		}

		List<string> CleanRecycleBin()
		{
			var logs = new List<string>();

			// clean version contents
			this.VersionDataSources.ForEach(dataSource =>
			{
				try
				{
					RepositoryMediator.CleanVersionContents(dataSource);
					logs.Add($"Clean old version contents successful [{dataSource}]");
				}
				catch (Exception ex)
				{
					logs.Add($"Error occurred while cleaning old version contents of data source [{dataSource}]\r\n[{ex.GetType()}]: {ex.Message}\r\nStack: {ex.StackTrace}");
					var inner = ex.InnerException;
					var count = 1;
					while (inner != null)
					{
						logs.Add($"-- Inner ({count}) -----\r\n[{inner.GetType()}]: {inner.Message}\r\nStack: {inner.StackTrace}");
						count++;
						inner = inner.InnerException;
					}
					logs.Add("----------------------------------------------------------------------");
				}
			});

			// clean trash contents
			this.TrashDataSources.ForEach(dataSource =>
			{
				try
				{
					RepositoryMediator.CleanTrashContents(dataSource);
					logs.Add($"Clean old trash contents successful [{dataSource}]");
				}
				catch (Exception ex)
				{
					logs.Add($"Error occurred while cleaning old trash contents of data source [{dataSource}]\r\n[{ex.GetType()}]: {ex.Message}\r\nStack: {ex.StackTrace}");
					var inner = ex.InnerException;
					var count = 1;
					while (inner != null)
					{
						logs.Add($"-- Inner ({count}) -----\r\n[{inner.GetType()}] : {inner.Message}\r\nStack: {inner.StackTrace}");
						count++;
						inner = inner.InnerException;
					}
					logs.Add("----------------------------------------------------------------------");
				}
			});

			return logs;
		}
		#endregion

		#region Run task scheduler
		async Task RunTaskSchedulerAsync()
		{
			// stop if its still running
			if (this.IsTaskSchedulerRunning)
				return;

			// prepare
			var tasks = this.Tasks.Values.Where(serviceInfo =>
			{
				var time = serviceInfo.Get<string>("Time");
				return serviceInfo.Instance == null && ("hourly".IsEquals(time) || $"{DateTime.Now.Hour}".IsEquals(time));
			})
			.ToList();

			if (tasks.Count < 1)
				return;

			// start
			this.IsTaskSchedulerRunning = true;
			var stopwatch = Stopwatch.StartNew();

			// run tasks
			var index = 0;
			while (index < tasks.Count)
			{
				// run a task
				var running = true;
				var task = tasks[index];
				var results = "";
				try
				{
					this.Tasks[task.ID].Instance = ExternalProcess.Start
					(
						task.Executable,
						this.PrepareTimestamps(task.Arguments),
						(sender, args) =>
						{
							var arguments = task.Arguments.ToArray(" ", true);
							for (var pos = 0; pos < arguments.Length; pos++)
							{
								if (arguments[pos].IsEquals("--password") && pos < arguments.Length - 1)
									arguments[pos + 1] = "***";
								else if (arguments[pos].IsStartsWith("/password:"))
									arguments[pos] = "/password:***";
								else if (arguments[pos].IsStartsWith("mongodb://"))
									arguments[pos] = "mongodb://***";
							}
							Global.OnProcess?.Invoke
							(
								"The task is completed" + "\r\n" +
								$"- Execution times: {((sender as Process).ExitTime - (sender as Process).StartTime).TotalMilliseconds.CastAs<long>().GetElapsedTimes()}" + "\r\n" +
								$"- Command: [{task.Executable + " " + this.PrepareTimestamps(arguments.Join(" "))}]" + "\r\n" +
								$"- Results: {results}"
							);
							this.Tasks[task.ID].Instance = null;
							running = false;
						},
						(sender, args) => results += string.IsNullOrWhiteSpace(args.Data) ? "" : $"\r\n{args.Data}"
					);
				}
				catch (Exception ex)
				{
					Global.OnError.Invoke($"Error occurred while running a scheduling task: {ex.Message}", ex);
					running = false;
				}

				// wait for completed
				while (running)
					try
					{
						await Task.Delay(1234, this.CancellationToken).ConfigureAwait(false);
					}
					catch (OperationCanceledException)
					{
						ExternalProcess.Stop(task.Instance);
						return;
					}
					catch (Exception)
					{
						running = false;
					}

				// run next
				index++;
			}

			// stop
			stopwatch.Stop();
			Global.OnProcess?.Invoke
			(
				"The task scheduler was completed with all tasks" + "\r\n" +
				$"- Number of tasks: {tasks.Count}" + "\r\n" +
				$"- Execution times: {stopwatch.GetElapsedTimes()}"
			);
			this.IsTaskSchedulerRunning = false;
		}
		#endregion

		#region Process inter-communicate messages
		async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			switch (message.Type)
			{
				case "Controller#RequestInfo":
					if (this.AllowRegisterBusinessServices || this.AllowRegisterHelperServices || this.AllowRegisterHelperTimers)
						await this.SendInterCommunicateMessageAsync("Controller#Info", this.Info.ToJson(), this.CancellationToken).ConfigureAwait(false);
					break;

				case "Service#RequestInfo":
					if (this.AllowRegisterBusinessServices)
					{
						var args = this.GetServiceArguments().Replace("/", "/run-").ToArray(' ');
						var os = Extensions.GetRuntimeOS();
						var platform = Extensions.GetRuntimePlatform();
						await Task.WhenAll(this.AvailableBusinessServices.Select(kvp => this.SendServiceInfoAsync(kvp.Key, kvp.Value.Instance?.Arguments, "Error".IsEquals(this.BusinessServices[kvp.Key]?.Get<string>("State")) ? false : true, kvp.Value.Instance != null))
							.Concat(this.BusinessServices.Select(kvp => this.SendInterCommunicateMessageAsync($"Service#UniqueInfo#{kvp.Key}", new JObject
							{
								{ "Name", Extensions.GetUniqueName(kvp.Key, args) },
								{ "OS", os },
								{ "Platform", platform }
							})))
						).ConfigureAwait(false);
					}
					break;

				case "Service#RequestUniqueInfo":
					if (this.AllowRegisterBusinessServices)
					{
						var name = (message.Data.Get<string>("Name") ?? "unknown").Trim().ToLower();
						if (this.AvailableBusinessServices.Keys.FirstOrDefault(n => n.Equals(name)) != null)
							await this.SendInterCommunicateMessageAsync($"Service#UniqueInfo#{name}", new JObject
							{
								{ "Name", Extensions.GetUniqueName(name, this.GetServiceArguments().Replace("/", "/run-").ToArray(' ')) },
								{ "OS", Extensions.GetRuntimeOS() },
								{ "Platform", Extensions.GetRuntimePlatform() }
							}).ConfigureAwait(false);
					}
					break;
			}
		}

		public async Task SendInterCommunicateMessageAsync(string type, JToken data = null, CancellationToken cancellationToken = default)
		{
			try
			{
				await new CommunicateMessage("APIGateway")
				{
					Type = type,
					Data = data ?? new JObject()
				}.SendAsync(cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Cannot send an inter-communicate message => {ex.Message}", ex);
			}
		}

		Task SendServiceInfoAsync(string name, string args, bool available, bool running)
			=> this.SendInterCommunicateMessageAsync
			(
				"Service#Info",
				new ServiceInfo
				{
					Name = name,
					UniqueName = Extensions.GetUniqueName(name, args?.ToArray(' ')),
					ControllerID = this.Info.ID,
					InvokeInfo = Extensions.GetInvokeInfo(),
					Available = available,
					Running = running
				}.ToJson(),
				this.CancellationToken
			);

		void SendServiceInfo(string name, string args, bool available, bool running)
			=> this.SendServiceInfoAsync(name, args, available, running).Execute();
		#endregion

		string PrepareTimestamps(string input)
		{
			input = input.IsContains("{node-id}") ? input.Replace(StringComparison.OrdinalIgnoreCase, "{node-id}", Global.NodeID) : input;
			input = input.IsContains("{iso-date}") ? input.Replace(StringComparison.OrdinalIgnoreCase, "{iso-date}", DateTime.Now.ToString("yyyy-MM-dd")) : input;
			input = input.IsContains("{iso-time}") ? input.Replace(StringComparison.OrdinalIgnoreCase, "{iso-time}", DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss")) : input;
			input = input.IsContains("{iso-time-seconds}") ? input.Replace(StringComparison.OrdinalIgnoreCase, "{iso-time-seconds}", DateTime.Now.ToString("yyyy.MM.dd.HH.mm.ss")) : input;
			input = input.IsContains("{iso-time-miliseconds}") ? input.Replace(StringComparison.OrdinalIgnoreCase, "{iso-time-miliseconds}", DateTime.Now.ToString("yyyy.MM.dd.HH.mm.ss.fff")) : input;
			input = input.IsContains("{iso-time-stamp}") ? input.Replace(StringComparison.OrdinalIgnoreCase, "{iso-time-stamp}", DateTime.Now.ToUnixTimestamp().ToString()) : input;
			return input;
		}
	}
}