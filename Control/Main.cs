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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class Controller : IServiceManager, IDisposable
	{
		/// <summary>
		/// Creates new instance of services controller
		/// </summary>
		/// <param name="cancellationToken"></param>
		public Controller(CancellationToken cancellationToken = default(CancellationToken))
		{
			this.CancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			this.LoggingService = new LoggingService(this.CancellationTokenSource.Token);
			this.RTUService = new RTUService();
			this.ServiceHosting = UtilityService.GetAppSetting("ServiceHosting", "VIEApps.Services.APIGateway").Trim();
			if (this.ServiceHosting.IsEndsWith(".exe") || this.ServiceHosting.IsEndsWith(".dll"))
				this.ServiceHosting = this.ServiceHosting.Left(this.ServiceHosting.Length - 4).Trim();
			this.ServiceHosting_x86 = UtilityService.GetAppSetting("ServiceHosting:x86", $"{this.ServiceHosting}.x86").Trim();
		}

		#region Properties
		public ServiceState State { get; private set; } = ServiceState.Initializing;
		public ControllerInfo Info { get; private set; } = null;
		CancellationTokenSource CancellationTokenSource { get; }
		internal IDisposable Communicator { get; private set; } = null;
		internal LoggingService LoggingService { get; } = null;
		internal RTUService RTUService { get; } = null;
		List<SystemEx.IAsyncDisposable> HelperServices { get; } = new List<SystemEx.IAsyncDisposable>();
		List<IDisposable> Timers { get; } = new List<IDisposable>();
		Dictionary<string, ServiceInfo> Tasks { get; } = new Dictionary<string, ServiceInfo>();
		string WorkingDirectory { get; } = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar.ToString();
		string ServiceHosting { get; }
		string ServiceHosting_x86 { get; }
		Dictionary<string, ServiceInfo> BusinessServices { get; } = new Dictionary<string, ServiceInfo>();
		ConcurrentDictionary<string, ControllerInfo> Controllers { get; } = new ConcurrentDictionary<string, ControllerInfo>();
		MailSender MailSender { get; set; } = null;
		WebHookSender WebhookSender { get; set; } = null;
		bool IsHouseKeeperRunning { get; set; } = false;
		bool IsTaskSchedulerRunning { get; set; } = false;
		bool IsDisposed { get; set; } = false;
		bool IsUserInteractive { get; set; } = false;

		/// <summary>
		/// Gets the number of registered helper serivces
		/// </summary>
		public int NumberOfHelperServices => this.HelperServices.Count;

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
		public void Start(string[] args = null, Func<Task> nextAsync = null)
		{
			// prepare arguments
			var stopwatch = Stopwatch.StartNew();
			this.IsUserInteractive = Environment.UserInteractive && args?.FirstOrDefault(a => a.StartsWith("/daemon")) == null;
			this.Info = new ControllerInfo
			{
				Host = Environment.MachineName.ToLower(),
				User = Environment.UserName.ToLower(),
				Platform = $"{RuntimeInformation.FrameworkDescription} @ {this.OSInfo}",
				Mode = this.IsUserInteractive ? "Interactive app" : "Background service"
			};
			this.Info.ID = $"{this.Info.User}-{this.Info.Host}-" + $"{this.Info.Platform}{this.Info.Mode}".ToLower().GenerateUUID();

			// prepare folders
			new List<string>
			{
				Global.StatusPath,
				LoggingService.LogsPath,
				MailSender.EmailsPath,
				WebHookSender.WebHooksPath
			}.Where(path => !Directory.Exists(path)).ForEach(path => Directory.CreateDirectory(path));

			// prepare business services
			if (ConfigurationManager.GetSection("net.vieapps.services") is AppConfigurationSectionHandler servicesConfiguration)
				if (servicesConfiguration.Section.SelectNodes("./add") is XmlNodeList services)
					services.ToList().ForEach(service =>
					{
						var name = service.Attributes["name"]?.Value.Trim().ToLower();
						var type = service.Attributes["type"]?.Value.Trim().Replace(" ", "");
						if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(type))
							this.BusinessServices[name] = new ServiceInfo(name, service.Attributes["executable"]?.Value.Trim(), type, new Dictionary<string, string> { { "Bitness", service.Attributes["bitness"]?.Value } });
					});

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
							this.Tasks[id] = new ServiceInfo(id, executable, arguments, new Dictionary<string, string> { { "Time", task.Attributes["time"]?.Value ?? "3" } });
						}
					});

			// start
			Global.OnProcess?.Invoke("The API Gateway Services Controller is starting");
			Global.OnProcess?.Invoke($"Version: {typeof(Controller).Assembly.GetVersion()}");
			Global.OnProcess?.Invoke($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})");
#if DEBUG
			Global.OnProcess?.Invoke($"Working mode: {(this.IsUserInteractive ? "Interactive app" : "Background service")} (DEBUG)");
#else
			Global.OnProcess?.Invoke($"Working mode: {(this.IsUserInteractive ? "Interactive app" : "Background service")} (RELEASE)");
#endif
			Global.OnProcess?.Invoke($"Working directory: {this.WorkingDirectory}");

			Global.OnProcess?.Invoke($"Attempting to connect to WAMP router [{WAMPConnections.GetRouterStrInfo()}]");
			Task.WaitAll(new[]
			{
				WAMPConnections.OpenIncomingChannelAsync(
					(sender, arguments) =>
					{
						Global.OnProcess?.Invoke($"The incoming channel is established - Session ID: {arguments.SessionId}");
						WAMPConnections.IncomingChannel.Update(WAMPConnections.IncomingChannelSessionID, "APIGateway", "Incoming (APIGateway Services Controller)");
						if (this.State == ServiceState.Initializing)
							this.State = ServiceState.Ready;

						this.Communicator?.Dispose();
						this.Communicator = WAMPConnections.IncomingChannel.RealmProxy.Services
							.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
							.Subscribe(
								async (message) => await this.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false),
								exception => Global.OnError?.Invoke($"Error occurred while fetching inter-communicate message: {exception.Message}", this.State == ServiceState.Connected ? exception : null)
							);
						Global.OnProcess?.Invoke($"The inter-communicate message updater is{(this.State == ServiceState.Disconnected ? " re-" : " ")}subscribed successful");

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
						.ContinueWith(task =>
						{
							if (this.State == ServiceState.Ready)
							{
								try
								{
									this.RegisterMessagingTimers();
									this.RegisterSchedulingTimers();
									Global.OnProcess?.Invoke($"The background workers & schedulers are registered - Number of scheduling timers: {this.NumberOfTimers:#,##0} - Number of scheduling tasks: {this.NumberOfTasks:#,##0}");
								}
								catch (Exception ex)
								{
									Global.OnError?.Invoke($"Error occurred while registering background workers & schedulers: {ex.Message}", ex);
								}

								var svcArgs = this.GetServiceArguments().Replace("/", "/call-");
								this.BusinessServices.ForEach(kvp => Task.Run(() => this.StartBusinessService(kvp.Key, svcArgs)).ConfigureAwait(false));
							}
						}, TaskContinuationOptions.OnlyOnRanToCompletion)
						.ContinueWith(async (task) =>
						{
							while (WAMPConnections.OutgoingChannel == null)
								await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
							await this.SendInterCommunicateMessageAsync("Controller#RequestInfo").ConfigureAwait(false);
						}, TaskContinuationOptions.OnlyOnRanToCompletion)
						.ContinueWith(async (task) =>
						{
							if (this.State == ServiceState.Ready && nextAsync != null)
								try
								{
									await nextAsync().ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									Global.OnError?.Invoke($"Error occurred while invoking the next action: {ex.Message}", ex);
								}
						}, TaskContinuationOptions.OnlyOnRanToCompletion)
						.ContinueWith(task =>
						{
							stopwatch.Stop();
							Global.OnProcess?.Invoke($"The API Gateway Services Controller is{(this.State == ServiceState.Disconnected ? " re-" : " ")}started successful - PID: {Process.GetCurrentProcess().Id} - Execution times: {stopwatch.GetElapsedTimes()}");
							this.State = ServiceState.Connected;
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

						else
						{
							Global.OnProcess?.Invoke($"The incoming channel to WAMP router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
							WAMPConnections.IncomingChannel.ReOpen(this.CancellationTokenSource.Token, Global.OnError, "Incoming");
						}
					},
					(sender, arguments) =>
					{
						Global.OnError?.Invoke($"The incoming channel to WAMP router got an error: {arguments.Exception.Message}", arguments.Exception);
					}
				),
				WAMPConnections.OpenOutgoingChannelAsync(
					(sender, arguments) =>
					{
						Global.OnProcess?.Invoke($"The outgoing channel is established - Session ID: {arguments.SessionId}");
						WAMPConnections.OutgoingChannel.Update(WAMPConnections.OutgoingChannelSessionID, "APIGateway", "Outgoing (APIGateway Services Controller)");
					},
					(sender, arguments) =>
					{
						if (WAMPConnections.ChannelsAreClosedBySystem || arguments.CloseType.Equals(SessionCloseType.Goodbye))
							Global.OnProcess?.Invoke($"The outgoing channel is closed - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");

						else
						{
							Global.OnProcess?.Invoke($"The outgoing channel to WAMP router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
							WAMPConnections.OutgoingChannel.ReOpen(this.CancellationTokenSource.Token, Global.OnError, "Outgoing");
						}
					},
					(sender, arguments) =>
					{
						Global.OnError?.Invoke($"The outgoging channel to WAMP router got an error: {arguments.Exception.Message}", arguments.Exception);
					}
				)
			}, this.CancellationTokenSource.Token);
		}

		public void Stop()
		{
			Task.Run(() => this.SendInterCommunicateMessageAsync("Controller#Disconnect", this.Info.ToJson())).ConfigureAwait(false);

			MailSender.SaveMessages();
			WebHookSender.SaveMessages();

			this.Timers.ForEach(timer => timer.Dispose());
			this.Tasks.Values.ForEach(serviceInfo => ExternalProcess.Stop(serviceInfo.Instance));
			this.BusinessServices.Keys.ToList().ForEach(name => this.StopBusinessService(name, () => Global.OnProcess?.Invoke($"[{name.ToLower()}] => The service is stopped")));

			this.Communicator?.Dispose();
			this.LoggingService?.FlushAllLogs();

			this.HelperServices.ForEach(async (service) => await service.DisposeAsync().ConfigureAwait(false));
			this.CancellationTokenSource.Cancel();

			WAMPConnections.CloseChannels();

			this.State = ServiceState.Disconnected;
		}

		public List<ControllerInfo> GetAvailableControllers() => this.Controllers.Values.ToList();
		#endregion

		#region Start/Stop business service
		/// <summary>
		/// Gets the collection of available businness services
		/// </summary>
		/// <returns></returns>
		public Dictionary<string, string> GetAvailableBusinessServices()
			=> this.BusinessServices.ToDictionary(kvp => $"net.vieapps.services.{kvp.Key}", kvp => kvp.Value.Arguments);

		/// <summary>
		/// Gets the state that determines a business service is available or not
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public bool IsBusinessServiceAvailable(string name)
			=> !string.IsNullOrWhiteSpace(name) && this.BusinessServices.ContainsKey(name.Trim().ToLower());

		/// <summary>
		/// Gets the state that determines a business service is running or not
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public bool IsBusinessServiceRunning(string name)
			=> this.GetServiceProcess(name) != null;

		/// <summary>
		/// Gets the process information of a business service
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public ExternalProcess.Info GetServiceProcess(string name)
			=> !string.IsNullOrWhiteSpace(name) && this.BusinessServices.TryGetValue(name.Trim().ToLower(), out ServiceInfo info)
				? info.Instance
				: null;

		string OSInfo => $"{(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})";

		/// <summary>
		/// Gets the arguments for starting a business service with environment information
		/// </summary>
		/// <returns></returns>
		public string GetServiceArguments()
			=> $"/user:{Environment.UserName?.ToLower().UrlEncode()} /host:{Environment.MachineName?.ToLower().UrlEncode()} /platform:{RuntimeInformation.FrameworkDescription.UrlEncode()} /os:{this.OSInfo.UrlEncode()}";

		/// <summary>
		/// Starts a business service
		/// </summary>
		/// <param name="name"></param>
		/// <param name="arguments"></param>
		public void StartBusinessService(string name, string arguments = null)
		{
			name = name?.Trim().ToLower();
			if (!this.IsBusinessServiceAvailable(name))
			{
				var ex = new ServiceNotFoundException($"The service [net.vieapps.services.{name}] is not found");
				Global.OnError?.Invoke($"[{name}] => {ex.Message}", ex);
				return;
			}

			else if (this.IsBusinessServiceRunning(name))
				return;

			Global.OnProcess?.Invoke($"[{name}] => The service is starting");
			try
			{
				var serviceInfo = this.BusinessServices[name];
				serviceInfo.Extra.TryGetValue("Bitness", out string bitness);

				var serviceHosting = !string.IsNullOrWhiteSpace(serviceInfo.Executable)
						? serviceInfo.Executable
						: "x86".IsEquals(bitness) || "32bits".IsEquals(bitness) ? this.ServiceHosting_x86 : this.ServiceHosting;

				if (!File.Exists(serviceHosting + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "")))
					throw new FileNotFoundException($"The service hosting is not found [{serviceHosting + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "")}]");

				var serviceArguments = $"/svc:{serviceInfo.Arguments} /agc:r {this.GetServiceArguments().Replace("/", "/run-")} {arguments ?? ""}".Trim();
				this.BusinessServices[name].Instance = ExternalProcess.Start(
					serviceHosting,
					serviceArguments,
					(sender, args) =>
					{
						this.BusinessServices[name].Instance = null;
						Global.OnServiceStopped?.Invoke(name, $"The sevice is stopped");
						Task.Run(() => this.SendInterCommunicateMessageAsync("Service#Info", new JObject
						{
							{ "URI", $"net.vieapps.services.{name}" },
							{ "State", "Stopped" },
							{ "Controller", this.Info.ID }
						})).ConfigureAwait(false);
					},
					(sender, args) => Global.OnGotServiceMessage?.Invoke(name, args.Data)
				);
				Global.OnServiceStarted?.Invoke(name, $"The service is started - Process ID: {this.BusinessServices[name].Instance.ID} [{serviceHosting} {serviceArguments}]");
				Task.Run(() => this.SendInterCommunicateMessageAsync("Service#Info", new JObject
				{
					{ "URI", $"net.vieapps.services.{name}" },
					{ "State", "Running" },
					{ "Controller", this.Info.ID },
					{ "Hosting", serviceHosting },
					{ "Arguments", serviceArguments }
				})).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"[{name}] => Cannot start the service: {ex.Message}", ex is FileNotFoundException ? null : ex);
			}
		}

		/// <summary>
		/// Stops a business service
		/// </summary>
		/// <param name="name"></param>
		public void StopBusinessService(string name)
		{
			name = name?.Trim().ToLower();
			if (!this.IsBusinessServiceAvailable(name))
			{
				var ex = new ServiceNotFoundException($"The service [net.vieapps.services.{name}] is not found");
				Global.OnError?.Invoke($"[{name}] => {ex.Message}", ex);
				return;
			}

			var serviceProcess = this.GetServiceProcess(name);
			if (serviceProcess == null)
				return;

			Global.OnProcess?.Invoke($"[{name}] => The service is stopping");
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				try
				{
					var processInfo = ExternalProcess.Start(serviceProcess.FilePath, serviceProcess.Arguments.Replace("/agc:r", "/agc:s"), "");
					processInfo.Process.Dispose();
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while stopping the service [{name}] => {ex.Message}", ex);
				}
			else
				ExternalProcess.Stop(this.BusinessServices[name].Instance, info => { }, ex => Global.OnError?.Invoke($"Error occurred while stopping the service [{name}] => {ex.Message}", ex));
		}

		/// <summary>
		/// Starts a business service
		/// </summary>
		/// <param name="name"></param>
		/// <param name="arguments"></param>
		/// <param name="onStarted"></param>
		public void StartBusinessService(string name, string arguments, Action onStarted)
		{
			if (!this.IsBusinessServiceRunning(name))
			{
				this.StartBusinessService(name, arguments);
				onStarted?.Invoke();
			}
		}

		/// <summary>
		/// Stops a business service
		/// </summary>
		/// <param name="name"></param>
		/// <param name="onStopped"></param>
		public void StopBusinessService(string name, Action onStopped)
		{
			if (this.IsBusinessServiceRunning(name))
			{
				this.StopBusinessService(name);
				onStopped?.Invoke();
			}
		}
		#endregion

		#region Register helper services
		async Task RegisterHelperServicesAsync()
		{
			try
			{
				this.HelperServices.Add(await WAMPConnections.IncomingChannel.RealmProxy.Services.RegisterCallee(this, RegistrationInterceptor.Create(this.Info.ID)).ConfigureAwait(false));
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

			this.HelperServices.Add(await WAMPConnections.IncomingChannel.RealmProxy.Services.RegisterCallee(this.RTUService, RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.OnProcess?.Invoke($"The real-time update (RTU) service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");

			this.HelperServices.Add(await WAMPConnections.IncomingChannel.RealmProxy.Services.RegisterCallee(this.LoggingService, RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.OnProcess?.Invoke($"The logging service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");

			this.HelperServices.Add(await WAMPConnections.IncomingChannel.RealmProxy.Services.RegisterCallee(new MessagingService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.OnProcess?.Invoke($"The messaging service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");

			Global.OnProcess?.Invoke($"Number of helper services: {this.NumberOfHelperServices:#,##0}");
		}
		#endregion

		#region Register timers for working with background workers & schedulers
		IDisposable StartTimer(Action action, int interval, int delay = 0)
		{
			interval = interval < 1 ? 1 : interval;
			var timer = Observable.Timer(TimeSpan.FromMilliseconds(delay > 0 ? delay : interval * 1000), TimeSpan.FromSeconds(interval)).Subscribe(_ => action?.Invoke());
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
						Global.OnError.Invoke($"Error occurred while sending web-hook messages: {ex.Message}", ex);
					}
					finally
					{
						this.MailSender = null;
					}
			}, 15);

			// send web hook messages (35 seconds)
			this.StartTimer(async () =>
			{
				if (this.WebhookSender == null)
					try
					{
						this.WebhookSender = new WebHookSender(this.CancellationTokenSource.Token);
						await this.WebhookSender.ProcessAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError.Invoke($"Error occurred while sending web-hook messages: {ex.Message}", ex);
					}
					finally
					{
						this.WebhookSender = null;
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
			}, UtilityService.GetAppSetting("Logs:FlushInterval", "60").CastAs<int>());
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
			Global.OnProcess($"Prepare recycle-bin information [{(this._serviceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this._workingDirectory : "")}{this._serviceHosting}]");
#endif

			new List<string>
			{
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.exe.config",
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.dll.config",
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.x86.exe.config",
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.x86.dll.config"
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

			new List<string>
			{
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.exe.config",
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.dll.config",
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.x86.exe.config",
				$"{(this.ServiceHosting.IndexOf(Path.DirectorySeparatorChar) < 0 ? this.WorkingDirectory : "")}{this.ServiceHosting}.x86.dll.config"
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
				.Where(serviceInfo => serviceInfo.Instance == null && ("hourly".IsEquals(serviceInfo.Extra["Time"]) || $"{DateTime.Now.Hour}".IsEquals(serviceInfo.Extra["Time"])))
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
							var command = task.Executable + " " + task.Arguments;
							var pos = command.PositionOf("/password:");
							while (pos > -1)
							{
								var next = command.IndexOf(" ", pos);
								command = command.Remove(pos + 10, next - pos - 11);
								command = command.Insert(pos + 10, "*****");
								pos = command.PositionOf("/password:", pos + 1);
							}
							var startTime = (sender as Process).StartTime;
							var exitTime = (sender as Process).ExitTime;
							var elapsedTimes = (exitTime - startTime).TotalMilliseconds.CastAs<long>().GetElapsedTimes();
							Global.OnProcess?.Invoke(
								"The task is completed" + "\r\n" +
								$"- Execution times: {elapsedTimes}" + "\r\n" +
								$"- Command: [{command.Trim()}]" + "\r\n" +
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
		public Task SendInterCommunicateMessageAsync(string type, JToken data = null)
			=> this.RTUService.SendInterCommunicateMessageAsync(new CommunicateMessage
			{
				ServiceName = "APIGateway",
				Type = type,
				Data = data ?? new JObject()
			});

		public Action<CommunicateMessage> OnInterCommunicateMessageReceived { get; set; }

		async Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			// controller
			ControllerInfo controllerInfo = null;
			if (message.Type.IsStartsWith("Controller#"))
				switch (message.Type.ToArray('#').Last().ToLower())
				{
					case "requestinfo":
						await this.SendInterCommunicateMessageAsync("Controller#Info", this.Info.ToJson()).ConfigureAwait(false);
						break;

					case "info":
					case "connect":
						controllerInfo = message.Data.FromJson<ControllerInfo>();
						this.Controllers.TryAdd(controllerInfo.ID, controllerInfo);
						break;

					case "disconnect":
						controllerInfo = message.Data.FromJson<ControllerInfo>();
						this.Controllers.TryRemove(controllerInfo.ID, out ControllerInfo ctrl);
						break;
				}

			// services
			if (message.Type.IsEquals("Service#RequestInfo"))
				await Task.WhenAll(this.BusinessServices.Select(kvp => this.SendInterCommunicateMessageAsync("Service#Info", new JObject
				{
					{ "URI", $"net.vieapps.services.{kvp.Key}" },
					{ "State", kvp.Value.Instance != null ? "Running" : "Stopped" },
					{ "Controller", this.Info.ID },
					{ "Hosting", kvp.Value.Instance != null ? kvp.Value.Instance.FilePath : ""  },
					{ "Arguments", kvp.Value.Instance != null ? kvp.Value.Instance.Arguments : "" }
				}))).ConfigureAwait(false);

			// registered handler
			this.OnInterCommunicateMessageReceived?.Invoke(message);
		}
		#endregion

		#region Dispose
		public void Dispose()
		{
			if (!this.IsDisposed)
			{
				this.IsDisposed = true;
				this.Stop();
				GC.SuppressFinalize(this);
			}
		}

		~Controller()
		{
			this.Dispose();
			this.CancellationTokenSource.Dispose();
		}
		#endregion

	}

	#region Information of Controller & Services
	[Serializable]
	public class ControllerInfo
	{
		public ControllerInfo() { }
		public string ID { get; set; }
		public string Host { get; set; }
		public string User { get; set; }
		public string Platform { get; set; }
		public string Mode { get; set; }
		public Dictionary<string, string> Extra { get; }
	}

	internal class ServiceInfo
	{
		public ServiceInfo(string id = "", string executable = "", string arguments = "", Dictionary<string, string> extra = null)
		{
			this.ID = id;
			this.Executable = executable;
			this.Arguments = arguments;
			this.Extra = new Dictionary<string, string>(extra ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase);
		}
		public string ID { get; set; }
		public string Executable { get; set; }
		public string Arguments { get; set; }
		public Dictionary<string, string> Extra { get; }
		public ExternalProcess.Info Instance { get; set; }
	}
	#endregion

}