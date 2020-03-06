#region Related components
using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
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
				GC.SuppressFinalize(this);
			}
		}

		public void Dispose()
			=> this.DisposeAsync().Wait();

		~Controller()
			=> this.Dispose();

		#region Process Info
		public class ProcessInfo
		{
			public ProcessInfo(string id, string executable, string arguments = "", Dictionary<string, object> extra = null)
			{
				this.ID = id;
				this.Executable = executable;
				this.Arguments = arguments;
				this.Extra = new Dictionary<string, object>(extra ?? new Dictionary<string, object>(), StringComparer.OrdinalIgnoreCase);
			}

			public string ID { get; }

			public string Executable { get; }

			public string Arguments { get; }

			public Dictionary<string, object> Extra { get; }

			public ExternalProcess.Info Instance { get; internal set; }

			public void Set<T>(string name, T value)
				=> this.Extra[name] = value;

			public void Set<T>(IDictionary<string, T> items)
				=> items?.ForEach(kvp => this.Set(kvp.Key, kvp.Value));

			public T Get<T>(string name, T @default = default)
				=> this.Extra.TryGetValue(name, out object value) && value != null && value is T
					? (T)value
					: @default;
		}
		#endregion

		#region Properties
		public ServiceState State { get; private set; } = ServiceState.Initializing;

		public ControllerInfo Info { get; private set; }

		public CancellationTokenSource CancellationTokenSource { get; private set; }

		IDisposable InterCommunicator { get; set; }

		IDisposable UpdateCommunicator { get; set; }

		LoggingService LoggingService { get; set; }

		IRTUService RTUService { get; set; }

		List<IAsyncDisposable> HelperServices { get; } = new List<IAsyncDisposable>();

		List<IDisposable> Timers { get; } = new List<IDisposable>();

		Dictionary<string, ProcessInfo> Tasks { get; } = new Dictionary<string, ProcessInfo>(StringComparer.OrdinalIgnoreCase);

		string WorkingDirectory { get; } = $"{Directory.GetCurrentDirectory()}{Path.DirectorySeparatorChar}";

		string ServiceHosting { get; set; } = "VIEApps.Services.APIGateway";

		Dictionary<string, ProcessInfo> BusinessServices { get; } = new Dictionary<string, ProcessInfo>(StringComparer.OrdinalIgnoreCase);

		MailSender MailSender { get; set; }

		WebHookSender WebHookSender { get; set; }

		bool IsHouseKeeperRunning { get; set; } = false;

		bool IsTaskSchedulerRunning { get; set; } = false;

		public bool IsDisposed { get; private set; } = false;

		bool IsUserInteractive { get; set; } = false;

		bool AllowRegisterHelperServices { get; set; } = true;

		bool AllowRegisterHelperTimers { get; set; } = true;

		bool AllowRegisterBusinessServices { get; set; } = true;

		DateTime ClientPingTime { get; set; } = DateTime.Now;

		DateTime ClientSchedulingTime { get; set; } = DateTime.Now;

		List<string> VersionDataSources { get; } = new List<string>();

		List<string> TrashDataSources { get; } = new List<string>();

		/// <summary>
		/// Gets the number of registered helper serivces
		/// </summary>
		public int NumberOfHelperServices => this.HelperServices.Count - 1;

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
		public void Start(
			string[] args = null,
			Action<object, WampSessionCreatedEventArgs> onIncomingConnectionEstablished = null,
			Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished = null,
			Action<Controller> next = null
		)
		{
			// prepare arguments
			var stopwatch = Stopwatch.StartNew();
			this.IsUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(a => a.StartsWith("/daemon")) == null;

			var mode = this.IsUserInteractive ? "Interactive app" : "Background service";
			this.Info = new ControllerInfo
			{
				ID = $"{Environment.UserName}-{Environment.MachineName}-".ToLower() + $"{Extensions.GetRuntimePlatform()}{mode}".ToLower().GenerateUUID(),
				User = Environment.UserName.ToLower(),
				Host = Environment.MachineName.ToLower(),
				Platform = $"{Extensions.GetRuntimePlatform()}",
				Mode = mode,
				Available = true
			};

			if (args?.FirstOrDefault(a => a.StartsWith("/no-helper-services")) != null)
				this.AllowRegisterHelperServices = false;

			if (args?.FirstOrDefault(a => a.StartsWith("/no-helper-timers")) != null)
				this.AllowRegisterHelperTimers = false;

			if (args?.FirstOrDefault(a => a.StartsWith("/no-business-services")) != null)
				this.AllowRegisterBusinessServices = false;

			// prepare directories
			try
			{
				new[]
				{
					Global.StatusPath,
					LoggingService.LogsPath,
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
							this.BusinessServices[name] = new ProcessInfo(name, service.Attributes["executable"]?.Value?.Trim(), type);
					});
			}

			// prepare scheduling tasks
			if (ConfigurationManager.GetSection(UtilityService.GetAppSetting("Section:TaskScheduler", "net.vieapps.task.scheduler")) is AppConfigurationSectionHandler tasksConfiguration && tasksConfiguration.Section.SelectNodes("task") is XmlNodeList tasks)
				tasks.ToList().ForEach(task =>
				{
					var executable = task.Attributes["executable"]?.Value.Trim();
					if (!string.IsNullOrWhiteSpace(executable) && File.Exists(executable))
					{
						var arguments = (task.Attributes["arguments"]?.Value ?? "").Trim();
						var id = (executable + " " + arguments).ToLower().GenerateUUID();
						this.Tasks[id] = new ProcessInfo(id, executable, arguments, new Dictionary<string, object>
						{
							{ "Time", Int32.TryParse(task.Attributes["time"]?.Value, out var time) ? time.ToString() : task.Attributes["time"]?.Value ?? "3" }
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
			Global.OnProcess?.Invoke($"Number of business services: {this.BusinessServices.Count}");
			Global.OnProcess?.Invoke($"Number of scheduling tasks: {this.Tasks.Count}");

			// prepare database settings
			this.PrepareDatabaseSettings();

			// prepare logging service
			if (this.AllowRegisterHelperServices)
				this.LoggingService = new LoggingService(this.CancellationTokenSource.Token);

			// connect to API Gateway Router
			var attemptingCounter = 0;

			void connectRouter()
			{
				Task.Run(() => connectRouterAsync()).ConfigureAwait(false);
			}

			async Task connectRouterAsync()
			{
				attemptingCounter++;
				Global.OnProcess?.Invoke($"Attempting to connect to API Gateway Router [{new Uri(Router.GetRouterStrInfo()).GetResolvedURI()}] #{attemptingCounter}");
				try
				{
					await Router.ConnectAsync(
						async (sender, arguments) =>
						{
							Global.OnProcess?.Invoke($"The incoming channel is established - Session ID: {arguments.SessionId}");
							Router.IncomingChannel.Update(Router.IncomingChannelSessionID, "APIGateway", "Incoming (APIGateway Controller)");
							if (this.State == ServiceState.Initializing)
								this.State = ServiceState.Ready;

							this.InterCommunicator?.Dispose();
							this.InterCommunicator = Router.IncomingChannel.RealmProxy.Services
								.GetSubject<CommunicateMessage>("messages.services.apigateway")
								.Subscribe(
									async message => await this.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false),
									exception => Global.OnError?.Invoke($"Error occurred while fetching an inter-communicate message of API Gateway => {exception.Message}", this.State == ServiceState.Connected ? exception : null)
								);
							Global.OnProcess?.Invoke($"The communicator of API Gateway was{(this.State == ServiceState.Disconnected ? " re-" : " ")}subscribed successful");

							this.UpdateCommunicator?.Dispose();
							this.UpdateCommunicator = Router.IncomingChannel.RealmProxy.Services
								.GetSubject<UpdateMessage>("messages.update")
								.Subscribe(
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
									await Task.Delay(UtilityService.GetRandomNumber(456, 789), this.CancellationTokenSource.Token).ConfigureAwait(false);
									await this.RegisterHelperServicesAsync().ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									Global.OnError?.Invoke($"Error occurred while{(this.State == ServiceState.Disconnected ? " re-" : " ")}registering the helper services => {ex.Message}", ex);
								}
							}

							if (this.State == ServiceState.Ready)
							{
								if (this.AllowRegisterHelperTimers)
									try
									{
										this.RegisterMessagingTimers();
										this.RegisterTaskSchedulingTimers();
										this.RegisterClientIntervalTimers();
										Global.OnProcess?.Invoke($"The background workers & schedulers are registered - Number of scheduling timers: {this.NumberOfTimers:#,##0} - Number of scheduling tasks: {this.NumberOfTasks:#,##0}");
									}
									catch (Exception ex)
									{
										Global.OnError?.Invoke($"Error occurred while registering background workers & schedulers => {ex.Message}", ex);
									}

								if (this.AllowRegisterBusinessServices)
								{
									var svcArgs = this.GetServiceArguments().Replace("/", "/call-");
									Parallel.ForEach(this.BusinessServices, kvp => this.StartBusinessService(kvp.Key, svcArgs));
									this.StartTimer(() => this.WatchBusinessServices(), 30);
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
								await Task.Delay(UtilityService.GetRandomNumber(123, 456), this.CancellationTokenSource.Token).ConfigureAwait(false);
							this.RTUService = this.RTUService ?? Router.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IRTUService>(ProxyInterceptor.Create());

							if (this.AllowRegisterBusinessServices || this.AllowRegisterHelperServices || this.AllowRegisterHelperTimers)
								await this.SendInterCommunicateMessageAsync("Controller#Info", this.Info.ToJson(), this.CancellationTokenSource.Token).ConfigureAwait(false);

							await Task.Delay(UtilityService.GetRandomNumber(4567, 5678), this.CancellationTokenSource.Token).ConfigureAwait(false);
							await Task.WhenAll(
								this.SendInterCommunicateMessageAsync("Controller#RequestInfo", null, this.CancellationTokenSource.Token),
								this.SendInterCommunicateMessageAsync("Service#RequestInfo", null, this.CancellationTokenSource.Token)
							).ConfigureAwait(false);
						},
						(sender, arguments) =>
						{
							if (this.State == ServiceState.Connected)
							{
								stopwatch.Restart();
								this.State = ServiceState.Disconnected;
							}

							if (Router.ChannelsAreClosedBySystem || arguments.CloseType.Equals(SessionCloseType.Goodbye))
								Global.OnProcess?.Invoke($"The incoming channel is closed - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
							else if (Router.IncomingChannel != null)
							{
								Global.OnProcess?.Invoke($"The incoming channel to API Gateway Router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
								Router.IncomingChannel.ReOpen(this.CancellationTokenSource.Token, Global.OnError, "Incoming");
							}
						},
						(sender, arguments) => Global.OnError?.Invoke($"Got an unexpected error of the incoming channel to API Gateway Router => {arguments.Exception?.Message}", arguments.Exception),
						async (sender, arguments) =>
						{
							Global.OnProcess?.Invoke($"The outgoing channel is established - Session ID: {arguments.SessionId}");
							Router.OutgoingChannel.Update(Router.OutgoingChannelSessionID, "APIGateway", "Outgoing (APIGateway Controller)");

							while (Router.IncomingChannel == null || Router.OutgoingChannel == null)
								await Task.Delay(UtilityService.GetRandomNumber(123, 456), this.CancellationTokenSource.Token).ConfigureAwait(false);
							this.RTUService = this.RTUService ?? Router.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IRTUService>(ProxyInterceptor.Create());

							try
							{
								onOutgoingConnectionEstablished?.Invoke(sender, arguments);
							}
							catch (Exception ex)
							{
								Global.OnError?.Invoke($"Error occurred while invoking \"{nameof(onOutgoingConnectionEstablished)}\" => {ex.Message}", ex);
							}
						},
						(sender, arguments) =>
						{
							if (Router.ChannelsAreClosedBySystem || arguments.CloseType.Equals(SessionCloseType.Goodbye))
								Global.OnProcess?.Invoke($"The outgoing channel is closed - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
							else if (Router.OutgoingChannel != null)
							{
								Global.OnProcess?.Invoke($"The outgoing channel to API Gateway Router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
								Router.OutgoingChannel.ReOpen(this.CancellationTokenSource.Token, Global.OnError, "Outgoing");
							}
						},
						(sender, arguments) => Global.OnError?.Invoke($"Got an unexpected error of the outgoging channel to API Gateway Router => {arguments.Exception?.Message}", arguments.Exception),
						this.CancellationTokenSource.Token
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while connecting to API Gateway Router => {ex.Message}", ex);
					if (attemptingCounter < 13)
					{
						await Task.Delay(UtilityService.GetRandomNumber(456, 789), this.CancellationTokenSource.Token).ConfigureAwait(false);
						connectRouter();
					}
					else
						Global.OnError?.Invoke($"Don't attempt to connect to API Gateway Router after {attemptingCounter} tried times => need to check API Gateway Router", null);
				}
			}

			connectRouter();
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
					await Task.WhenAll(
						this.BusinessServices.Keys.ForEachAsync(async (name, cancellationToken) => await Task.Run(() => this.StopBusinessService(name, false, false)).ConfigureAwait(false), this.CancellationTokenSource.Token),
						this.Tasks.Values.ForEachAsync(async (serviceInfo, cancellationToken) => await Task.Run(() => ExternalProcess.Stop(serviceInfo.Instance, null, null, 789)).ConfigureAwait(false), this.CancellationTokenSource.Token)
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while disposing external processes (services & tasks) => {ex.Message}", ex);
				}

			// dispose all timers
			try
			{
				this.Timers.ForEach(timer => timer.Dispose());
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
					await this.SendInterCommunicateMessageAsync("Controller#Disconnect", this.Info.ToJson(), this.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Cannot send the updating information => {ex.Message}", ex);
				}

			// dipose all helper services
			if (this.AllowRegisterHelperServices)
			{
				await this.HelperServices.ForEachAsync(async (service, cancellationToken) =>
				{
					try
					{
						await service.DisposeAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke($"Cannot dispose the helper service => {ex.Message}", ex);
					}
				}, this.CancellationTokenSource.Token).ConfigureAwait(false);
				Global.OnProcess?.Invoke($"{this.HelperServices.Count:#,##0} helper service(s) of the API Gateway Controller was disposed");
			}

			// do clean-up tasks
			try
			{
				this.MailSender?.Dispose();
				MailSender.SaveMessages();

				this.WebHookSender?.Dispose();
				WebHookSender.SaveMessages();

				await (this.LoggingService != null ? this.LoggingService.FlushAsync() : Task.CompletedTask).ConfigureAwait(false);
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

				this.RTUService = null;
				await Router.DisconnectAsync().ConfigureAwait(false);

				this.State = ServiceState.Disconnected;
				this.CancellationTokenSource.Cancel();

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
			=> this.StopAsync().Wait();

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
						if (!string.IsNullOrWhiteSpace(connectionStringName) && connectionStrings.ContainsKey(connectionStringName))
						{
							var attribute = dataSourceNode.OwnerDocument.CreateAttribute("connectionString");
							attribute.Value = connectionStrings[connectionStringName];
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
					foreach (XmlNode repository in repositoryNodes)
					{
						name = repository.Attributes["versionDataSource"]?.Value;
						if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.TrashDataSources.IndexOf(name) < 0)
							this.TrashDataSources.Add(name);

						name = repository.Attributes["trashDataSource"]?.Value;
						if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.TrashDataSources.IndexOf(name) < 0)
							this.TrashDataSources.Add(name);
					}
			}

			// settings of services
			new[]
			{
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.exe.config",
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.dll.config"
			}.Where(filename => File.Exists(filename)).ForEach(filename =>
			{
				var xml = new XmlDocument();
				xml.LoadXml(UtilityService.ReadTextFile(filename));

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
								if (!string.IsNullOrWhiteSpace(connectionStringName) && connectionStrings.ContainsKey(connectionStringName))
								{
									var attribute = xml.CreateAttribute("connectionString");
									attribute.Value = connectionStrings[connectionStringName];
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
						foreach (XmlNode repository in repositoryNodes)
						{
							name = repository.Attributes["versionDataSource"]?.Value;
							if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.TrashDataSources.IndexOf(name) < 0)
								this.TrashDataSources.Add(name);

							name = repository.Attributes["trashDataSource"]?.Value;
							if (!string.IsNullOrWhiteSpace(name) && dataSources.ContainsKey(name) && this.TrashDataSources.IndexOf(name) < 0)
								this.TrashDataSources.Add(name);
						}
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

			var loggingDataSource = RepositoryMediator.GetDataSource(UtilityService.GetAppSetting("Logs:DataSource"));
			if (this.AllowRegisterHelperServices && loggingDataSource != null)
				Task.Run(() =>
				{
					Global.OnProcess?.Invoke($"Initialize the entity (LoggingItem) for storing logs into database with data source: {loggingDataSource.Name}");
					RepositoryStarter.Initialize(this.GetType().Assembly, (msg, ex) =>
					{
						if (ex != null)
							Global.OnError?.Invoke(msg, ex);
						else
							Global.OnProcess?.Invoke(msg);
					});
				})
				.ContinueWith(async _ =>
				{
					if (loggingDataSource.Mode.Equals(RepositoryMode.SQL))
						await RepositoryStarter.EnsureSqlSchemasAsync(RepositoryMediator.GetEntityDefinition<LoggingItem>(), loggingDataSource, (msg, ex) =>
						{
							if (ex != null)
								Global.OnError?.Invoke(msg, ex);
							else
								Global.OnProcess?.Invoke(msg);
						}).ConfigureAwait(false);
					else if (loggingDataSource.Mode.Equals(RepositoryMode.NoSQL))
						await RepositoryStarter.EnsureNoSqlIndexesAsync(RepositoryMediator.GetEntityDefinition<LoggingItem>(), loggingDataSource, (msg, ex) =>
						{
							if (ex != null)
								Global.OnError?.Invoke(msg, ex);
							else
								Global.OnProcess?.Invoke(msg);
						}).ConfigureAwait(false);
				}, TaskContinuationOptions.OnlyOnRanToCompletion)
				.ConfigureAwait(false);
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
			=> this.BusinessServices.Where(kvp => this.IsBusinessServiceAvailable(kvp.Key)).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

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
			return processInfo != null
				? processInfo.Get<string>("NotAvailable") == null
				: false;
		}

		/// <summary>
		/// Gets the state that determines a business service is running or not
		/// </summary>
		/// <param name="name">The name of a service</param>
		/// <returns></returns>
		public bool IsBusinessServiceRunning(string name)
		{
			var processInfo = this.GetServiceProcessInfo(name);
			return processInfo != null
				? processInfo.Instance != null && "Running".IsEquals(processInfo.Get<string>("State"))
				: false;
		}

		/// <summary>
		/// Gets the arguments for starting a business service with environment information
		/// </summary>
		/// <returns></returns>
		public string GetServiceArguments()
			=> $"/user:{Environment.UserName.ToLower().UrlEncode()} /host:{Environment.MachineName.ToLower().UrlEncode()} /platform:{RuntimeInformation.FrameworkDescription.UrlEncode()} /os:{Extensions.GetRuntimePlatform(false).UrlEncode()}";

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
				if (!File.Exists(serviceHosting + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "")))
					throw new FileNotFoundException($"The service hosting is not found [{serviceHosting + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "")}]");

				this.BusinessServices[name].Instance = ExternalProcess.Start(
					serviceHosting,
					$"/svc:{this.BusinessServices[name].Arguments} /agc:r {this.GetServiceArguments().Replace("/", "/run-")} {arguments ?? ""} /controller-id:{this.Info.ID}".Trim(),
					(sender, args) =>
					{
						this.BusinessServices[name].Instance = null;
						Global.OnServiceStopped?.Invoke(name, $"The sevice was stopped{("Error".IsEquals(this.BusinessServices[name].Get<string>("State")) ? $" ({this.BusinessServices[name].Get<string>("Error")})" : "")}");
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
				Global.OnServiceStarted?.Invoke(name, $"The service was {re}started - Process ID: {this.BusinessServices[name].Instance.ID}");
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
		public void StopBusinessService(string name, bool available, bool sendServiceInfo)
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
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				try
				{
					var info = ExternalProcess.Start(processInfo.Instance.FilePath, processInfo.Instance.Arguments.Replace("/agc:r", "/agc:s"), "");
					using (info.Process)
					{
						this.BusinessServices[name].Set("State", "Stopped");
					}
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
				ExternalProcess.Stop(
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
			=> this.StopBusinessService(name, true, true);

		void WatchBusinessServices()
		{
			var svcArgs = this.GetServiceArguments().Replace("/", "/call-");
			this.BusinessServices
				.Where(kvp => kvp.Value.Instance == null && "Running".IsEquals(kvp.Value.Get<string>("State")))
				.Select(kvp => kvp.Key)
				.ForEach(name => this.StartBusinessService(name, svcArgs));
		}
		#endregion

		#region Register helper services
		async Task RegisterHelperServicesAsync()
		{
			try
			{
				this.HelperServices.Add(await Router.IncomingChannel.RealmProxy.Services.RegisterCallee(this, RegistrationInterceptor.Create(this.Info.ID, WampInvokePolicy.Single)).ConfigureAwait(false));
				Global.OnProcess?.Invoke($"The managing service was{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");
			}
			catch (WampSessionNotEstablishedException)
			{
				throw;
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Error occurred while{(this.State == ServiceState.Disconnected ? " re-" : " ")}registering the managing service: {ex.Message}", ex);
			}

			if (this.AllowRegisterHelperServices)
			{
				this.HelperServices.Add(await Router.IncomingChannel.RealmProxy.Services.RegisterCallee(this.LoggingService, RegistrationInterceptor.Create()).ConfigureAwait(false));
				Global.OnProcess?.Invoke($"The logging service was{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");

				this.HelperServices.Add(await Router.IncomingChannel.RealmProxy.Services.RegisterCallee(new RTUService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
				Global.OnProcess?.Invoke($"The real-time update (RTU) service was{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");

				this.HelperServices.Add(await Router.IncomingChannel.RealmProxy.Services.RegisterCallee(new MessagingService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
				Global.OnProcess?.Invoke($"The messaging service was{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");
			}

			Global.OnProcess?.Invoke($"Number of helper services: {this.NumberOfHelperServices:#,##0}");
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
					action?.Invoke();
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while running timer => {ex.Message}", ex);
				}
			});
			this.Timers.Add(timer);
			return timer;
		}

		void RegisterMessagingTimers()
		{
			// send email messages (15 seconds)
			if (!Int32.TryParse(UtilityService.GetAppSetting("TimerInterval:Mail", "15"), out var interval))
				interval = 15;
			this.StartTimer(async () =>
			{
				if (this.MailSender == null)
					try
					{
						this.MailSender = new MailSender(this.CancellationTokenSource.Token);
						await this.MailSender.ProcessAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke($"Error occurred while sending email messages: {ex.Message}", ex);
					}
					finally
					{
						this.MailSender = null;
					}
			}, interval);

			// send web hook messages (35 seconds)
			if (!Int32.TryParse(UtilityService.GetAppSetting("TimerInterval:WebHook", "35"), out interval))
				interval = 35;
			this.StartTimer(async () =>
			{
				if (this.WebHookSender == null)
					try
					{
						this.WebHookSender = new WebHookSender(this.CancellationTokenSource.Token);
						await this.WebHookSender.ProcessAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke($"Error occurred while sending web-hook messages: {ex.Message}", ex);
					}
					finally
					{
						this.WebHookSender = null;
					}
			}, interval);
		}

		void RegisterTaskSchedulingTimers()
		{
			// flush logs (DEBUG: 5 seconds - Other: 45 seconds)
#if DEBUG
			var interval = 5;
#else
			if (!Int32.TryParse(UtilityService.GetAppSetting("TimerInterval:FlushLogs", "45"), out int interval))
				interval = 45;
#endif
			this.StartTimer(async () => await (this.LoggingService != null ? this.LoggingService.FlushAsync() : Task.CompletedTask).ConfigureAwait(false), interval);

			// house keeper (hourly)
			this.StartTimer(() => this.RunHouseKeeper(), 60 * 60);

			// task scheduler (hourly)
			var runTaskSchedulerOnFirstLoad = false;
			if (ConfigurationManager.GetSection(UtilityService.GetAppSetting("Section:TaskScheduler", "net.vieapps.task.scheduler")) is AppConfigurationSectionHandler config)
				runTaskSchedulerOnFirstLoad = "true".IsEquals(config.Section.Attributes["runOnFirstLoad"]?.Value);
			this.StartTimer(async () => await this.RunTaskSchedulerAsync().ConfigureAwait(false), 65 * 60, runTaskSchedulerOnFirstLoad ? 5678 : 0);
		}

		void RegisterClientIntervalTimers()
		{
			// ping - default: 2 minutes
			if (!Int32.TryParse(UtilityService.GetAppSetting("TimerInterval:Ping", "120"), out var pingInterval))
				pingInterval = 120;
			this.StartTimer(() =>
			{
				if ((DateTime.Now - this.ClientPingTime).TotalSeconds >= pingInterval)
					Task.Run(async () => await this.RTUService.SendUpdateMessageAsync(new UpdateMessage
					{
						Type = "Ping",
						DeviceID = "*",
					}, this.CancellationTokenSource.Token).ConfigureAwait(false))
					.ContinueWith(_ => this.ClientPingTime = DateTime.Now, TaskContinuationOptions.OnlyOnRanToCompletion)
					.ConfigureAwait(false);
			}, pingInterval + 13);

			// scheduler (update online status, signal to run scheduler at client, ...) - default: 15 minutes
			if (!Int32.TryParse(UtilityService.GetAppSetting("TimerInterval:Scheduler", "900"), out var scheduleInterval))
				scheduleInterval = 900;
			this.StartTimer(() =>
			{
				if ((DateTime.Now - this.ClientSchedulingTime).TotalSeconds >= scheduleInterval)
					Task.Run(async () => await this.RTUService.SendUpdateMessageAsync(new UpdateMessage
					{
						Type = "Scheduler",
						DeviceID = "*",
					}, this.CancellationTokenSource.Token).ConfigureAwait(false))
					.ContinueWith(_ => this.ClientSchedulingTime = DateTime.Now, TaskContinuationOptions.OnlyOnRanToCompletion)
					.ConfigureAwait(false);
			}, scheduleInterval + 13);
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
				LoggingService.LogsPath
			};
			paths.Append(UtilityService.GetAppSetting("HouseKeeper:Folders")?.ToHashSet('|') ?? new HashSet<string>());

			var excludedSubFolders = UtilityService.GetAppSetting("HouseKeeper:ExcludedSubFolders")?.ToList('|');
			var excludedFileExtensions = UtilityService.GetAppSetting("HouseKeeper:ExcludedFileExtensions")?.ToLower().ToHashSet('|') ?? new HashSet<string>();
			var remainHours = UtilityService.GetAppSetting("HouseKeeper:RemainHours", "120").CastAs<int>();
			var specialFileExtensions = UtilityService.GetAppSetting("HouseKeeper:SpecialFileExtensions")?.ToLower().ToHashSet('|') ?? new HashSet<string>();
			var specialRemainHours = UtilityService.GetAppSetting("HouseKeeper:SpecialRemainHours", "12").CastAs<int>();

			// process
			var remainTime = DateTime.Now.AddHours(0 - remainHours);
			var specialRemainTime = DateTime.Now.AddHours(0 - specialRemainHours);
			var counter = 0;
			paths.Select(path => new DirectoryInfo(path)).Where(dir => dir.Exists).ForEach(dir =>
			{
				// delete old files
				UtilityService.GetFiles(dir.FullName, "*.*", true, excludedSubFolders)
					.Where(file => !excludedFileExtensions.Contains(file.Extension) && file.LastWriteTime < (specialFileExtensions.Contains(file.Extension) ? specialRemainTime : remainTime))
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
					.Where(d => d.GetFiles().Length < 1)
					.ForEach(d =>
					{
						try
						{
							d.Delete(true);
						}
						catch { }
					});
			});

			// debug logs
			remainTime = DateTime.Now.AddHours(0 - 36);
			UtilityService.GetFiles(LoggingService.LogsPath, "*.*").Where(file => file.LastWriteTime < remainTime).ForEach(file =>
			{
				try
				{
					file.Delete();
					counter++;
				}
				catch { }
			});

			// clean recycle-bin contents
			var logs = this.CleanRecycleBin();

			// done
			stopwatch.Stop();
			Global.OnProcess?.Invoke(
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
			var tasks = this.Tasks.Values
				.Where(serviceInfo =>
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
					this.Tasks[task.ID].Instance = ExternalProcess.Start(
						task.Executable,
						task.Arguments,
						(sender, args) =>
						{
							var arguments = task.Arguments.ToArray(" ", true);
							for (var pos = 0; pos < arguments.Length; pos++)
							{
								if (arguments[pos].IsEquals("--password") && pos < arguments.Length - 1)
									arguments[pos + 1] = "***";
								else if (arguments[pos].IsStartsWith("/password:"))
									arguments[pos] = "/password:***";
							}
							Global.OnProcess?.Invoke(
								"The task is completed" + "\r\n" +
								$"- Execution times: {((sender as Process).ExitTime - (sender as Process).StartTime).TotalMilliseconds.CastAs<long>().GetElapsedTimes()}" + "\r\n" +
								$"- Command: [{task.Executable + " " + arguments.Join(" ")}]" + "\r\n" +
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
						await Task.Delay(1234, this.CancellationTokenSource.Token).ConfigureAwait(false);
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
			Global.OnProcess?.Invoke(
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
						await this.SendInterCommunicateMessageAsync("Controller#Info", this.Info.ToJson(), this.CancellationTokenSource.Token).ConfigureAwait(false);
					break;

				case "Service#RequestInfo":
					if (this.AllowRegisterBusinessServices)
					{
						var args = this.GetServiceArguments().Replace("/", "/call-").ToArray(' ');
						var osPlatform = Extensions.GetRuntimeOS();
						await Task.WhenAll(this.AvailableBusinessServices.Select(kvp => this.SendServiceInfoAsync(kvp.Key, kvp.Value.Instance?.Arguments, "Error".IsEquals(this.BusinessServices[kvp.Key]?.Get<string>("State")) ? false : true, kvp.Value.Instance != null))
							.Concat(this.BusinessServices.Select(kvp => this.SendInterCommunicateMessageAsync($"Service#UniqueInfo#{kvp.Key}", new JObject
							{
								{ "OSPlatform", osPlatform },
								{ "Name", Extensions.GetUniqueName(kvp.Key, args) }
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
								{ "OSPlatform", Extensions.GetRuntimeOS() },
								{ "Name", Extensions.GetUniqueName(name, this.GetServiceArguments().Replace("/", "/call-").ToArray(' ')) }
							}).ConfigureAwait(false);
					}
					break;
			}
		}

		public async Task SendInterCommunicateMessageAsync(string type, JToken data = null, CancellationToken cancellationToken = default)
		{
			if (this.RTUService == null && Router.OutgoingChannel != null)
				this.RTUService = Router.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IRTUService>(ProxyInterceptor.Create());

			try
			{
				await this.RTUService.SendInterCommunicateMessageAsync(new CommunicateMessage("APIGateway")
				{
					Type = type,
					Data = data ?? new JObject()
				}, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Cannot send an inter-communicate message => {ex.Message}", ex);
			}
		}

		Task SendServiceInfoAsync(string name, string args, bool available, bool running)
		{
			var arguments = (args?.ToArray(' ') ?? new string[] { }).Where(arg => !arg.IsStartsWith("/controller-id:")).ToArray();
			var invokeInfo = arguments.FirstOrDefault(a => a.IsStartsWith("/call-user:")) ?? "";

			if (!string.IsNullOrWhiteSpace(invokeInfo))
			{
				invokeInfo = invokeInfo.Replace(StringComparison.OrdinalIgnoreCase, "/call-user:", "").UrlDecode();
				var host = arguments.FirstOrDefault(a => a.IsStartsWith("/call-host:"));
				var platform = arguments.FirstOrDefault(a => a.IsStartsWith("/call-platform:"));
				var os = arguments.FirstOrDefault(a => a.IsStartsWith("/call-os:"));
				if (!string.IsNullOrWhiteSpace(host) && !string.IsNullOrWhiteSpace(platform) && !string.IsNullOrWhiteSpace(os))
					invokeInfo += $" [Host: {host.Replace(StringComparison.OrdinalIgnoreCase, "/call-host:", "").UrlDecode()} - Platform: {platform.Replace(StringComparison.OrdinalIgnoreCase, "/call-platform:", "").UrlDecode()} @ {os.Replace(StringComparison.OrdinalIgnoreCase, "/call-os:", "").UrlDecode()}]";
			}

			return this.SendInterCommunicateMessageAsync(
				"Service#Info",
				new ServiceInfo
				{
					Name = name,
					UniqueName = Extensions.GetUniqueName(name, arguments),
					ControllerID = this.Info.ID,
					InvokeInfo = invokeInfo,
					Available = available,
					Running = running
				}.ToJson(),
				this.CancellationTokenSource.Token
			);
		}

		void SendServiceInfo(string name, string args, bool available, bool running)
			=> Task.Run(() => this.SendServiceInfoAsync(name, args, available, running)).ConfigureAwait(false);
		#endregion

	}
}