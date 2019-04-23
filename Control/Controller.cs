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
using System.Runtime.InteropServices;

using WampSharp.V2.Realm;
using WampSharp.V2.Client;
using WampSharp.V2.Core.Contracts;

using Newtonsoft.Json.Linq;

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
		/// <param name="cancellationToken"></param>
		public Controller(CancellationToken cancellationToken = default(CancellationToken))
		{
			this.CancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			this.LoggingService = new LoggingService(this.CancellationTokenSource.Token);
		}

		public void Dispose()
		{
			if (!this.IsDisposed)
			{
				this.IsDisposed = true;
				this.Stop();
				this.CancellationTokenSource.Dispose();
				GC.SuppressFinalize(this);
			}
		}

		~Controller() => this.Dispose();

		#region Process Info
		public class ProcessInfo
		{
			public ProcessInfo(string id = "", string executable = "", string arguments = "", Dictionary<string, object> extra = null)
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

			public T Get<T>(string name, T @default = default(T))
				=> this.Extra.TryGetValue(name, out object value) && value != null && value is T
					? (T)value
					: @default;
		}
		#endregion

		#region Properties
		public ServiceState State { get; private set; } = ServiceState.Initializing;

		public ControllerInfo Info { get; private set; } = null;

		public CancellationTokenSource CancellationTokenSource { get; private set; }

		IDisposable InterCommunicator { get; set; } = null;

		LoggingService LoggingService { get; } = null;

		IRTUService RTUService { get; set; } = null;

		List<SystemEx.IAsyncDisposable> HelperServices { get; } = new List<SystemEx.IAsyncDisposable>();

		List<IDisposable> Timers { get; } = new List<IDisposable>();

		Dictionary<string, ProcessInfo> Tasks { get; } = new Dictionary<string, ProcessInfo>(StringComparer.OrdinalIgnoreCase);

		string WorkingDirectory { get; } = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar.ToString();

		string ServiceHosting { get; set; } = "VIEApps.Services.APIGateway";

		Dictionary<string, ProcessInfo> BusinessServices { get; } = new Dictionary<string, ProcessInfo>(StringComparer.OrdinalIgnoreCase);

		MailSender MailSender { get; set; } = null;

		WebHookSender WebHookSender { get; set; } = null;

		bool IsHouseKeeperRunning { get; set; } = false;

		bool IsTaskSchedulerRunning { get; set; } = false;

		bool IsDisposed { get; set; } = false;

		bool IsUserInteractive { get; set; } = false;

		bool AllowRegisterHelperServices { get; set; } = true;

		bool AllowRegisterHelperTimers { get; set; } = true;

		bool AllowRegisterBusinessServices { get; set; } = true;

		IDisposable PingCommunicator { get; set; } = null;

		DateTime PingTime { get; set; } = DateTime.Now;

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
		public void Start(string[] args = null, Action<object, WampSessionCreatedEventArgs> onIncomingChannelEstablished = null, Action<object, WampSessionCreatedEventArgs> onOutgoingChannelEstablished = null, Func<Task> nextAsync = null)
		{
			// prepare arguments
			var stopwatch = Stopwatch.StartNew();
			this.IsUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(a => a.StartsWith("/daemon")) == null;
			this.Info = new ControllerInfo
			{
				User = Environment.UserName.ToLower(),
				Host = Environment.MachineName.ToLower(),
				Platform = $"{Extensions.GetRuntimePlatform()}",
				Mode = this.IsUserInteractive ? "Interactive app" : "Background service",
				Available = true
			};
			this.Info.ID = $"{this.Info.User}-{this.Info.Host}-" + $"{this.Info.Platform}{this.Info.Mode}".ToLower().GenerateUUID();

			if (args?.FirstOrDefault(a => a.StartsWith("/no-helper-services")) != null)
				this.AllowRegisterHelperServices = false;

			if (args?.FirstOrDefault(a => a.StartsWith("/no-helper-timers")) != null)
				this.AllowRegisterHelperTimers = false;

			if (args?.FirstOrDefault(a => a.StartsWith("/no-business-services")) != null)
				this.AllowRegisterBusinessServices = false;

			// prepare folders
			new[]
			{
				Global.StatusPath,
				LoggingService.LogsPath,
				MailSender.EmailsPath,
				WebHookSender.WebHooksPath
			}.Where(path => !Directory.Exists(path)).ForEach(path => Directory.CreateDirectory(path));

			// prepare business services
			if (ConfigurationManager.GetSection("net.vieapps.services") is AppConfigurationSectionHandler servicesConfiguration)
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
			if (ConfigurationManager.GetSection("net.vieapps.task.scheduler") is AppConfigurationSectionHandler tasksConfiguration)
				if (tasksConfiguration.Section.SelectNodes("task") is XmlNodeList tasks)
					tasks.ToList().ForEach(task =>
					{
						var executable = task.Attributes["executable"]?.Value.Trim();
						if (!string.IsNullOrWhiteSpace(executable) && File.Exists(executable))
						{
							var arguments = (task.Attributes["arguments"]?.Value ?? "").Trim();
							var id = (executable + " " + arguments).ToLower().GenerateUUID();
							this.Tasks[id] = new ProcessInfo(id, executable, arguments, new Dictionary<string, object>
							{
								{ "Time", Int32.TryParse(task.Attributes["time"]?.Value, out int time) ? time.ToString() : task.Attributes["time"]?.Value ?? "3" }
							});
						}
					});

			// start
			Global.OnProcess?.Invoke("The VIEApps NGX API Gateway Controller is starting");
			Global.OnProcess?.Invoke($"Version: {typeof(Controller).Assembly.GetVersion()}");
			Global.OnProcess?.Invoke($"Platform: {Extensions.GetRuntimePlatform()}");
#if DEBUG
			Global.OnProcess?.Invoke($"Working mode: {(this.IsUserInteractive ? "Interactive app" : "Background service")} (DEBUG)");
#else
			Global.OnProcess?.Invoke($"Working mode: {(this.IsUserInteractive ? "Interactive app" : "Background service")} (RELEASE)");
#endif
			Global.OnProcess?.Invoke($"Starting arguments: {args?.Join(" ") ?? "None"}");
			Global.OnProcess?.Invoke($"Working directory: {this.WorkingDirectory}");
			Global.OnProcess?.Invoke($"Number of business services: {this.BusinessServices.Count}");
			Global.OnProcess?.Invoke($"Number of scheduling tasks: {this.Tasks.Count}");

			var attemptingCounter = 0;

			void connectWAMPRouter()
			{
				Task.Run(() => connectWAMPRouterAsync()).ConfigureAwait(false);
			}

			async Task connectWAMPRouterAsync()
			{
				attemptingCounter++;
				Global.OnProcess?.Invoke($"Attempting to connect to WAMP router [{new Uri(WAMPConnections.GetRouterStrInfo()).GetResolvedURI()}] #{attemptingCounter}");
				try
				{
					await Task.WhenAll(
						WAMPConnections.OpenIncomingChannelAsync(
							(sender, arguments) =>
							{
								onIncomingChannelEstablished?.Invoke(sender, arguments);
								Global.OnProcess?.Invoke($"The incoming channel is established - Session ID: {arguments.SessionId}");
								WAMPConnections.IncomingChannel.Update(WAMPConnections.IncomingChannelSessionID, "APIGateway", "Incoming (APIGateway)");
								if (this.State == ServiceState.Initializing)
									this.State = ServiceState.Ready;

								this.InterCommunicator?.Dispose();
								this.InterCommunicator = WAMPConnections.IncomingChannel.RealmProxy.Services
									.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
									.Subscribe(
										async message => await this.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false),
										exception => Global.OnError?.Invoke($"Error occurred while fetching inter-communicate message: {exception.Message}", this.State == ServiceState.Connected ? exception : null)
									);
								Global.OnProcess?.Invoke($"The inter-communicate message updater is{(this.State == ServiceState.Disconnected ? " re-" : " ")}subscribed successful");

								this.PingCommunicator?.Dispose();
								this.PingCommunicator = WAMPConnections.IncomingChannel.RealmProxy.Services
									.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages")
									.Subscribe(
										message =>
										{
											if (message.Type.IsEquals("Ping"))
												this.PingTime = DateTime.Now;
										},
										exception => Global.OnError?.Invoke($"Error occurred while fetching ping-communicate message: {exception.Message}", this.State == ServiceState.Connected ? exception : null)
									);
								Global.OnProcess?.Invoke($"The ping-communicate message updater is{(this.State == ServiceState.Disconnected ? " re-" : " ")}subscribed successful");

								Task.Run(async () =>
								{
									try
									{
										await this.RegisterHelperServicesAsync().ConfigureAwait(false);
									}
									catch
									{
										try
										{
											await Task.Delay(UtilityService.GetRandomNumber(456, 789)).ConfigureAwait(false);
											await this.RegisterHelperServicesAsync().ConfigureAwait(false);
										}
										catch (Exception ex)
										{
											Global.OnError?.Invoke($"Error occurred while{(this.State == ServiceState.Disconnected ? " re-" : " ")}registering the helper services: {ex.Message}", ex);
										}
									}
								})
								.ContinueWith(_ =>
								{
									if (this.State == ServiceState.Ready)
									{
										if (this.AllowRegisterHelperTimers)
											try
											{
												this.RegisterMessagingTimers();
												this.RegisterSchedulingTimers();
												this.RegisterPingTimers();
												Global.OnProcess?.Invoke($"The background workers & schedulers are registered - Number of scheduling timers: {this.NumberOfTimers:#,##0} - Number of scheduling tasks: {this.NumberOfTasks:#,##0}");
											}
											catch (Exception ex)
											{
												Global.OnError?.Invoke($"Error occurred while registering background workers & schedulers: {ex.Message}", ex);
											}

										if (this.AllowRegisterBusinessServices)
										{
											var svcArgs = this.GetServiceArguments().Replace("/", "/call-");
											Parallel.ForEach(this.BusinessServices, kvp => this.StartBusinessService(kvp.Key, svcArgs));
											this.StartTimer(() => this.WatchBusinessServices(), 30);
										}
									}
								}, TaskContinuationOptions.OnlyOnRanToCompletion)
								.ContinueWith(async _ =>
								{
									if (nextAsync != null && this.State == ServiceState.Ready)
										try
										{
											await nextAsync().ConfigureAwait(false);
										}
										catch (Exception ex)
										{
											Global.OnError?.Invoke($"Error occurred while invoking the next action: {ex.Message}", ex);
										}
								}, TaskContinuationOptions.OnlyOnRanToCompletion)
								.ContinueWith(_ =>
								{
									stopwatch.Stop();
									Global.OnProcess?.Invoke($"The API Gateway Services Controller is{(this.State == ServiceState.Disconnected ? " re-" : " ")}started - PID: {Process.GetCurrentProcess().Id} - Execution times: {stopwatch.GetElapsedTimes()}");
									this.State = ServiceState.Connected;
								}, TaskContinuationOptions.OnlyOnRanToCompletion)
								.ContinueWith(async _ =>
								{
									if (this.AllowRegisterBusinessServices || this.AllowRegisterHelperServices || this.AllowRegisterHelperTimers)
									{
										while (WAMPConnections.IncomingChannel == null || WAMPConnections.OutgoingChannel == null)
											await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
										await this.SendInterCommunicateMessageAsync("Controller#Info", this.Info.ToJson(), this.CancellationTokenSource.Token).ConfigureAwait(false);
									}
								}, TaskContinuationOptions.OnlyOnRanToCompletion)
								.ContinueWith(async _ =>
								{
									await Task.Delay(UtilityService.GetRandomNumber(5678, 7890)).ConfigureAwait(false);
									await Task.WhenAll(
										this.SendInterCommunicateMessageAsync("Controller#RequestInfo"),
										this.SendInterCommunicateMessageAsync("Service#RequestInfo")
									).ConfigureAwait(false);
								}, TaskContinuationOptions.OnlyOnRanToCompletion)
								.ConfigureAwait(false);
							},
							(sender, arguments) =>
							{
								if (this.State == ServiceState.Connected)
								{
									stopwatch.Restart();
									this.State = ServiceState.Disconnected;
								}

								if (WAMPConnections.ChannelsAreClosedBySystem || arguments.CloseType.Equals(SessionCloseType.Goodbye))
									Global.OnProcess?.Invoke($"The incoming channel is closed - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
								else if (WAMPConnections.IncomingChannel != null)
								{
									Global.OnProcess?.Invoke($"The incoming channel to WAMP router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
									WAMPConnections.IncomingChannel.ReOpen(this.CancellationTokenSource.Token, Global.OnError, "Incoming");
								}
							},
							(sender, arguments) => Global.OnError?.Invoke($"The incoming channel to WAMP router got an error: {arguments.Exception?.Message}", arguments.Exception),
							this.CancellationTokenSource.Token
						),
						WAMPConnections.OpenOutgoingChannelAsync(
							(sender, arguments) =>
							{
								onOutgoingChannelEstablished?.Invoke(sender, arguments);
								Global.OnProcess?.Invoke($"The outgoing channel is established - Session ID: {arguments.SessionId}");
								WAMPConnections.OutgoingChannel.Update(WAMPConnections.OutgoingChannelSessionID, "APIGateway", "Outgoing (APIGateway)");
							},
							(sender, arguments) =>
							{
								if (WAMPConnections.ChannelsAreClosedBySystem || arguments.CloseType.Equals(SessionCloseType.Goodbye))
									Global.OnProcess?.Invoke($"The outgoing channel is closed - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
								else if (WAMPConnections.OutgoingChannel != null)
								{
									Global.OnProcess?.Invoke($"The outgoing channel to WAMP router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
									WAMPConnections.OutgoingChannel.ReOpen(this.CancellationTokenSource.Token, Global.OnError, "Outgoing");
								}
							},
							(sender, arguments) => Global.OnError?.Invoke($"The outgoging channel to WAMP router got an error: {arguments.Exception?.Message}", arguments.Exception),
							this.CancellationTokenSource.Token
						)
					).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while connecting to WAMP router => {ex.Message}", ex);
					if (attemptingCounter < 13)
					{
						await Task.Delay(UtilityService.GetRandomNumber(456, 789)).ConfigureAwait(false);
						connectWAMPRouter();
					}
					else
						Global.OnError?.Invoke($"Don't attempt to connect to WAMP router after {attemptingCounter} tried times => need to check WAMP router", null);
				}
			}

			connectWAMPRouter();
		}

		public void Stop()
		{
			Task.Run(async () =>
			{
				if (this.AllowRegisterBusinessServices || this.AllowRegisterHelperServices || this.AllowRegisterHelperTimers)
					try
					{
						await this.SendInterCommunicateMessageAsync("Controller#Disconnect", this.Info.ToJson()).ConfigureAwait(false);
#if DEBUG
						Global.OnProcess?.Invoke($"The updating message was sent when the controller is disconnected => {this.Info.ToJson()}");
#endif
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke($"Cannot send the updating information => {ex.Message}", ex);
					}
			})
			.ContinueWith(async _ => await this.HelperServices.ForEachAsync(async (service, token) =>
			{
				try
				{
					await service.DisposeAsync().ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Cannot dispose the helper service => {ex.Message}", ex);
				}
			}), TaskContinuationOptions.OnlyOnRanToCompletion)
			.ConfigureAwait(false);

			MailSender.SaveMessages();
			WebHookSender.SaveMessages();

			this.Timers.ForEach(timer => timer.Dispose());
			this.Tasks.Values.ForEach(serviceInfo => ExternalProcess.Stop(serviceInfo.Instance));
			this.BusinessServices.Keys.ForEach(name => this.StopBusinessService(name));

			this.InterCommunicator?.Dispose();
			this.PingCommunicator?.Dispose();
			this.MailSender?.Dispose();
			this.WebHookSender?.Dispose();
			this.LoggingService?.FlushAllLogs();
			this.CancellationTokenSource.Cancel();

			this.RTUService = null;
			this.State = ServiceState.Disconnected;
			WAMPConnections.CloseChannels();
			Global.OnProcess?.Invoke($"The API Gateway Services Controller is stopped");
		}
		#endregion

		#region Start/Stop business service
		/// <summary>
		/// Gets the process information of a business service
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public ProcessInfo GetServiceProcessInfo(string name)
			=> !string.IsNullOrWhiteSpace(name) && this.BusinessServices.TryGetValue(name.ToArray('.').Last().ToLower(), out ProcessInfo info) ? info : null;

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
			=> this.AvailableBusinessServices.ToDictionary(kvp => $"net.vieapps.services.{kvp.Key}", kvp => kvp.Value.Arguments);

		/// <summary>
		/// Gets the state that determines a business service is available or not
		/// </summary>
		/// <param name="name"></param>
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
		/// <param name="name"></param>
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
			=> $"/user:{Environment.UserName?.ToLower().UrlEncode()} /host:{Environment.MachineName?.ToLower().UrlEncode()} /platform:{RuntimeInformation.FrameworkDescription.UrlEncode()} /os:{Extensions.GetRuntimePlatform(false).UrlEncode()}";

		/// <summary>
		/// Starts a business service
		/// </summary>
		/// <param name="name"></param>
		/// <param name="arguments"></param>
		public void StartBusinessService(string name, string arguments = null)
		{
			if (!this.IsBusinessServiceAvailable(name))
			{
				var ex = new ServiceNotFoundException($"The service [net.vieapps.services.{name ?? "unknown"}] is not found");
				Global.OnError?.Invoke($"[{name ?? "unknown"}] => {ex.Message}", ex);
				return;
			}

			name = name.ToArray('.').Last().ToLower();
			if (this.IsBusinessServiceRunning(name))
				return;

			var re = "Running".IsEquals(this.BusinessServices[name].Get<string>("State")) ? "re-" : "";
			Global.OnProcess?.Invoke($"[{name}] => The service is {re}starting");
			var serviceArguments = $"/svc:{this.BusinessServices[name].Arguments} /agc:r {this.GetServiceArguments().Replace("/", "/run-")} {arguments ?? ""}".Trim();

			try
			{
				var serviceHosting = string.IsNullOrWhiteSpace(this.BusinessServices[name].Executable) ? this.ServiceHosting : this.BusinessServices[name].Executable;
				if (!File.Exists(serviceHosting + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "")))
					throw new FileNotFoundException($"The service hosting is not found [{serviceHosting + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "")}]");

				this.BusinessServices[name].Instance = ExternalProcess.Start(
					serviceHosting,
					serviceArguments,
					(sender, args) =>
					{
						this.BusinessServices[name].Instance = null;
						Global.OnServiceStopped?.Invoke(name, $"The sevice is stopped{("Error".IsEquals(this.BusinessServices[name].Get<string>("State")) ? $" ({this.BusinessServices[name].Get<string>("Error")})" : ("Stopped".IsEquals(this.BusinessServices[name].Get<string>("State")) ? "" : " (unexpected)"))}");
						Task.Run(() => this.SendServiceInfoAsync(name, false, serviceArguments)).ConfigureAwait(false);
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
				Global.OnServiceStarted?.Invoke(name, $"The service is {re}started - Process ID: {this.BusinessServices[name].Instance.ID}");
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
			finally
			{
				Task.Run(async () =>
				{
					await Task.Delay(UtilityService.GetRandomNumber(1234, 2345)).ConfigureAwait(false);
					if (this.IsBusinessServiceRunning(name))
						await Task.WhenAll(
							this.SendServiceInfoAsync(name, true, serviceArguments),
							this.SendInterCommunicateMessageAsync($"Service#UniqueInfo#{name}", new JObject
							{
								{ "OSPlatform", Extensions.GetRuntimeOS() },
								{ "Name", $"{Extensions.GetUniqueName(name, serviceArguments.ToArray(' '))}" }
							})
						).ConfigureAwait(false);
				}).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Stops a business service
		/// </summary>
		/// <param name="name"></param>
		public void StopBusinessService(string name)
		{
			name = !string.IsNullOrWhiteSpace(name) ? name.ToArray('.').Last().ToLower() : "unknown";
			if (!this.BusinessServices.ContainsKey(name))
			{
				var ex = new ServiceNotFoundException($"The service [net.vieapps.services.{name}] is not found");
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
				}
			else
				ExternalProcess.Stop(
					processInfo.Instance,
					info => this.BusinessServices[name].Set("State", "Stopped"),
					ex =>
					{
						Global.OnError?.Invoke($"Error occurred while stopping the service [{name}] => {ex.Message}", ex);
						this.BusinessServices[name].Set(new Dictionary<string, string>
						{
							{ "State", "Error" },
							{ "Error", ex.Message },
							{ "ErrorStack", ex.StackTrace }
						});
					}
				);
		}

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
				this.HelperServices.Add(await WAMPConnections.IncomingChannel.RealmProxy.Services.RegisterCallee(this, RegistrationInterceptor.Create(this.Info.ID, WampInvokePolicy.Single)).ConfigureAwait(false));
				Global.OnProcess?.Invoke($"The managing service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");
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
				this.HelperServices.Add(await WAMPConnections.IncomingChannel.RealmProxy.Services.RegisterCallee(this.LoggingService, RegistrationInterceptor.Create()).ConfigureAwait(false));
				Global.OnProcess?.Invoke($"The logging service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");

				this.HelperServices.Add(await WAMPConnections.IncomingChannel.RealmProxy.Services.RegisterCallee(new RTUService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
				Global.OnProcess?.Invoke($"The real-time update (RTU) service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");

				this.HelperServices.Add(await WAMPConnections.IncomingChannel.RealmProxy.Services.RegisterCallee(new MessagingService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
				Global.OnProcess?.Invoke($"The messaging service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");
			}

			while (WAMPConnections.OutgoingChannel == null)
				await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
			this.RTUService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IRTUService>(ProxyInterceptor.Create());

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
			}, 15);

			// send web hook messages (35 seconds)
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
			}, 35);
		}

		void RegisterSchedulingTimers()
		{
			// flush logs (DEBUG: 5 seconds - Other: 1 minute)
			this.StartTimer(() =>
			{
				this.LoggingService?.FlushAllLogs();
#if DEBUG
			}, 5);
#else
			}, UtilityService.GetAppSetting("Logs:FlushInterval", "45").CastAs<int>());
#endif

			// house keeper (hourly)
			this.PrepareRecycleBin();
			this.StartTimer(() => this.RunHouseKeeper(), 60 * 60);

			// task scheduler (hourly)
			var runTaskSchedulerOnFirstLoad = false;
			if (ConfigurationManager.GetSection("net.vieapps.task.scheduler") is AppConfigurationSectionHandler config)
				runTaskSchedulerOnFirstLoad = "true".IsEquals(config.Section.Attributes["runOnFirstLoad"]?.Value);
			this.StartTimer(async () => await this.RunTaskSchedulerAsync().ConfigureAwait(false), 65 * 60, runTaskSchedulerOnFirstLoad ? 5678 : 0);
		}

		void RegisterPingTimers()
			=> this.StartTimer(() =>
			{
				if ((DateTime.Now - this.PingTime).TotalSeconds >= 300)
					Task.Run(async () => await this.RTUService.SendUpdateMessageAsync(new UpdateMessage
					{
						Type = "Ping",
						DeviceID = "*",
					}, this.CancellationTokenSource.Token).ConfigureAwait(false))
					.ContinueWith(_ => this.PingTime = DateTime.Now, TaskContinuationOptions.OnlyOnRanToCompletion)
					.ConfigureAwait(false);
			}, 7 * 60);
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

		void PrepareRecycleBin()
		{
			var connectionStrings = new Dictionary<string, string>();
			var dataSources = new Dictionary<string, XmlNode>();
			var dbProviderFactories = new Dictionary<string, XmlNode>();

#if DEBUG
			Global.OnProcess($"Prepare recycle-bin information [{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}]");
#endif

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

				if (xml.DocumentElement.SelectNodes("/configuration/net.vieapps.repositories/dataSources/dataSource") is XmlNodeList dataSourceNodes)
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

				if (xml.DocumentElement.SelectNodes("/configuration/dbProviderFactories/add") is XmlNodeList dbProviderFactoryNodes)
					dbProviderFactoryNodes.ToList().ForEach(dbProviderFactoryNode =>
					{
						var invariant = dbProviderFactoryNode.Attributes["invariant"]?.Value;
						if (!string.IsNullOrWhiteSpace(invariant) && !dbProviderFactories.ContainsKey(invariant))
							dbProviderFactories[invariant] = dbProviderFactoryNode;
					});
			});

#if DEBUG
			Global.OnProcess?.Invoke($"Construct database provider factories ({dbProviderFactories.Count:#,##0})");
#endif

			RepositoryStarter.ConstructDbProviderFactories(dbProviderFactories.Values.ToList(), (msg, ex) =>
			{
				if (ex != null)
					Global.OnError?.Invoke(msg, ex);
				else
					Global.OnProcess?.Invoke(msg);
			});

#if DEBUG
			Global.OnProcess?.Invoke($"Construct data sources ({dataSources.Count:#,##0}) - Total of connection strings: {connectionStrings.Count:#,##0}");
#endif

			RepositoryStarter.ConstructDataSources(dataSources.Values.ToList(), (msg, ex) =>
			{
				if (ex != null)
					Global.OnError?.Invoke(msg, ex);
				else
					Global.OnProcess?.Invoke(msg);
			});
		}

		List<string> CleanRecycleBin()
		{
			// prepare data sources
			var versionDataSources = new List<string>();
			var trashDataSources = new List<string>();

			new[]
			{
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.exe.config",
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.dll.config"
			}.Where(filename => File.Exists(filename)).ForEach(filename =>
			{
				var xml = new XmlDocument();
				xml.LoadXml(UtilityService.ReadTextFile(filename));

				if (xml.DocumentElement.SelectSingleNode("/configuration/net.vieapps.repositories") is XmlNode root)
				{
					var name = root.Attributes["versionDataSource"]?.Value;
					if (!string.IsNullOrWhiteSpace(name) && versionDataSources.IndexOf(name) < 0)
						versionDataSources.Add(name);

					name = root.Attributes["trashDataSource"]?.Value;
					if (!string.IsNullOrWhiteSpace(name) && trashDataSources.IndexOf(name) < 0)
						trashDataSources.Add(name);

					if (root.SelectNodes("./repository") is XmlNodeList repositories)
						foreach (XmlNode repository in repositories)
						{
							name = repository.Attributes["versionDataSource"]?.Value;
							if (!string.IsNullOrWhiteSpace(name) && versionDataSources.IndexOf(name) < 0)
								versionDataSources.Add(name);

							name = repository.Attributes["trashDataSource"]?.Value;
							if (!string.IsNullOrWhiteSpace(name) && trashDataSources.IndexOf(name) < 0)
								trashDataSources.Add(name);
						}
				}
			});

			var logs = new List<string>();

			// clean version contents
			versionDataSources.ForEach(dataSource =>
			{
				try
				{
					RepositoryMediator.CleanVersionContents(dataSource);
					logs.Add($"Clean old version contents successful [{dataSource}]");
				}
				catch (Exception ex)
				{
					logs.Add($"Error occurred while cleaning old version contents of data source [{dataSource}]\r\n[{ex.GetType()}]: {ex.Message}\r\nStack:{ex.StackTrace}");
					var inner = ex.InnerException;
					var count = 1;
					while (inner != null)
					{
						logs.Add($"-- Inner ({count}) -----\r\n[{inner.GetType()}]: {inner.Message}\r\nStack:{inner.StackTrace}");
						count++;
						inner = inner.InnerException;
					}
					logs.Add("----------------------------------------------------------------------");
				}
			});

			// clean trash contents
			trashDataSources.ForEach(dataSource =>
			{
				try
				{
					RepositoryMediator.CleanTrashContents(dataSource);
					logs.Add($"Clean old trash contents successful [{dataSource}]");
				}
				catch (Exception ex)
				{
					logs.Add($"Error occurred while cleaning old trash contents of data source [{dataSource}]\r\n[{ex.GetType()}]: {ex.Message}\r\nStack:{ex.StackTrace}");
					var inner = ex.InnerException;
					var count = 1;
					while (inner != null)
					{
						logs.Add($"-- Inner ({count}) -----\r\n[{inner.GetType()}] : {inner.Message}\r\nStack:{inner.StackTrace}");
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
						var svcArgs = this.GetServiceArguments().Replace("/", "/call-").ToArray(' ');
						var osPlatform = Extensions.GetRuntimeOS();
						await Task.WhenAll(this.AvailableBusinessServices.Select(kvp => this.SendServiceInfoAsync(kvp.Key, kvp.Value.Instance != null, kvp.Value.Instance?.Arguments))
							.Concat(this.BusinessServices.Select(kvp => this.SendInterCommunicateMessageAsync($"Service#UniqueInfo#{kvp.Key}", new JObject
							{
								{ "OSPlatform", osPlatform },
								{ "Name", Extensions.GetUniqueName(kvp.Key, svcArgs) }
							})))).ConfigureAwait(false);
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

		public async Task SendInterCommunicateMessageAsync(string type, JToken data = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			if (this.RTUService == null && WAMPConnections.OutgoingChannel != null)
				this.RTUService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IRTUService>(ProxyInterceptor.Create());

			try
			{
				await this.RTUService.SendInterCommunicateMessageAsync(new CommunicateMessage
				{
					ServiceName = "APIGateway",
					Type = type,
					Data = data ?? new JObject()
				}, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Cannot send a communicate message => {ex.Message}", ex);
			}
		}

		async Task SendServiceInfoAsync(string name, bool state, string arguments)
		{
			var svcArgs = arguments?.ToArray(' ') ?? new string[] { };

			var invokeInfo = svcArgs.FirstOrDefault(a => a.IsStartsWith("/call-user:")) ?? "";
			if (!string.IsNullOrWhiteSpace(invokeInfo))
			{
				invokeInfo = invokeInfo.Replace(StringComparison.OrdinalIgnoreCase, "/call-user:", "").UrlDecode();
				var host = svcArgs.FirstOrDefault(a => a.IsStartsWith("/call-host:"));
				var platform = svcArgs.FirstOrDefault(a => a.IsStartsWith("/call-platform:"));
				var os = svcArgs.FirstOrDefault(a => a.IsStartsWith("/call-os:"));
				if (!string.IsNullOrWhiteSpace(host) && !string.IsNullOrWhiteSpace(platform) && !string.IsNullOrWhiteSpace(os))
					invokeInfo += $" [Host: {host.Replace(StringComparison.OrdinalIgnoreCase, "/call-host:", "").UrlDecode()} - Platform: {platform.Replace(StringComparison.OrdinalIgnoreCase, "/call-platform:", "").UrlDecode()} @ {os.Replace(StringComparison.OrdinalIgnoreCase, "/call-os:", "").UrlDecode()}]";
			}

			await this.SendInterCommunicateMessageAsync("Service#Info", new ServiceInfo
			{
				Name = name,
				UniqueName = Extensions.GetUniqueName(name, svcArgs),
				ControllerID = this.Info.ID,
				InvokeInfo = invokeInfo,
				Available = true,
				Running = state
			}.ToJson()).ConfigureAwait(false);
		}
		#endregion

	}
}