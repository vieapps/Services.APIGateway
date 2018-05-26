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
using System.Runtime.InteropServices;

using WampSharp.V2.Core.Contracts;
using WampSharp.V2.Realm;
using WampSharp.V2.Client;

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
			this._cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			this._loggingService = new LoggingService(this._cancellationTokenSource.Token);
			this._serviceHosting = UtilityService.GetAppSetting("ServiceHosting", "VIEApps.Services.APIGateway").Trim();
			if (this._serviceHosting.IsEndsWith(".exe") || this._serviceHosting.IsEndsWith(".dll"))
				this._serviceHosting = this._serviceHosting.Left(this._serviceHosting.Length - 4).Trim();
			this._serviceHosting_x86 = UtilityService.GetAppSetting("ServiceHosting:x86", $"{this._serviceHosting}.x86").Trim();
		}

		#region Attributes
		public ServiceState State { get; private set; } = ServiceState.Initializing;
		readonly CancellationTokenSource _cancellationTokenSource;
		internal IDisposable _communicator = null;
		readonly internal LoggingService _loggingService = null;
		readonly List<SystemEx.IAsyncDisposable> _helperServices = new List<SystemEx.IAsyncDisposable>();
		readonly List<IDisposable> _timers = new List<IDisposable>();
		readonly Dictionary<string, ServiceInfo> _tasks = new Dictionary<string, ServiceInfo>();
		readonly bool _isNETFramework = RuntimeInformation.FrameworkDescription.IsContains(".NET Framework");
		readonly string _workingDirectory = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar.ToString();
		readonly string _serviceHosting, _serviceHosting_x86;
		readonly Dictionary<string, ServiceInfo> _businessServices = new Dictionary<string, ServiceInfo>();
		MailSender _mailSender = null;
		WebHookSender _webhookSender = null;
		bool _isHouseKeeperRunning = false, _isTaskSchedulerRunning = false;
		bool _registerHelperServices = true, _registerBusinessServices = true, _registerTimers = true, _disposed = false;
		#endregion

		#region Start/Stop controller
		public void Start(string[] args = null, Func<Task> nextAsync = null)
		{
			// prepare arguments
			var stopwatch = Stopwatch.StartNew();
			if (Environment.UserInteractive)
			{
#if !DEBUG
				this._registerHelperServices = this._registerBusinessServices = this._registerTimers = false;
#endif
				if (args?.FirstOrDefault(a => a.IsEquals("/all")) != null)
					this._registerHelperServices = this._registerBusinessServices = this._registerTimers = true;
				else
					args?.ForEach(arg =>
					{
						if (arg.IsStartsWith("/helper-services:"))
							this._registerHelperServices = arg.IsEquals("/helper-services:true");
						else if (arg.IsStartsWith("/business-services:"))
							this._registerBusinessServices = arg.IsEquals("/business-services:true");
						else if (arg.IsStartsWith("/timers:"))
							this._registerTimers = arg.IsEquals("/timers:true");
					});
			}

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
							this._businessServices[name] = new ServiceInfo(name, service.Attributes["executable"]?.Value.Trim(), type, new Dictionary<string, string> { { "Bitness", service.Attributes["bitness"]?.Value } });
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
							this._tasks[id] = new ServiceInfo(id, executable, arguments, new Dictionary<string, string> { { "Time", task.Attributes["time"]?.Value ?? "3" } });
						}
					});

			// start
			Global.OnProcess?.Invoke("The API Gateway Services Controller is starting");
			Global.OnProcess?.Invoke($"Version: {typeof(Controller).Assembly.GetVersion()}");
			Global.OnProcess?.Invoke($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : $"Other OS")} {RuntimeInformation.OSArchitecture} ({RuntimeInformation.OSDescription.Trim()})");
#if DEBUG
			Global.OnProcess?.Invoke($"Working mode: {(Environment.UserInteractive ? "Interactive App" : "Background Service")} (DEBUG)");
#else
			Global.OnProcess?.Invoke($"Working mode: {(Environment.UserInteractive ? "Interactive App" : "Background Service")} (RELEASE)");
#endif
			Global.OnProcess?.Invoke($"Working directory: {this._workingDirectory}");

			Global.OnProcess?.Invoke($"Attempting to connect to WAMP router [{WAMPConnections.GetRouterStrInfo()}]");
			Task.WaitAll(new[]
			{
				WAMPConnections.OpenIncomingChannelAsync(
					(sender, arguments) =>
					{
						Global.OnProcess?.Invoke($"The incoming channel is established - Session ID: {arguments.SessionId}");
						if (this.State == ServiceState.Initializing)
							this.State = ServiceState.Ready;

						this._communicator?.Dispose();
						this._communicator = WAMPConnections.IncommingChannel.RealmProxy.Services
							.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
							.Subscribe(
								async (message) => await this.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false),
								exception => Global.OnError?.Invoke($"Error occurred while fetching inter-communicate message: {exception.Message}", this.State == ServiceState.Connected ? exception : null)
							);
						Global.OnProcess?.Invoke($"The inter-communicate message updater is{(this.State == ServiceState.Disconnected ? " re-" : " ")}subscribed successful");

						Task.Run(async () =>
						{
							if (this._registerHelperServices)
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
						.ContinueWith(async (task) =>
						{
							if (this.State == ServiceState.Ready)
							{
								if (this._registerTimers)
									try
									{
										this.RegisterMessagingTimers();
										this.RegisterSchedulingTimers();
										Global.OnProcess?.Invoke("The background workers & schedulers are registered");
									}
									catch (Exception ex)
									{
										Global.OnError?.Invoke($"Error occurred while registering background workers & schedulers: {ex.Message}", ex);
									}

								if (this._registerBusinessServices)
										this._businessServices.ForEach(kvp => Task.Run(() => this.StartBusinessService(kvp.Key)).ConfigureAwait(false));

								if (nextAsync != null)
									try
									{
										await nextAsync().ConfigureAwait(false);
									}
									catch (Exception ex)
									{
										Global.OnError?.Invoke($"Error occurred while invoking the next action: {ex.Message}", ex);
									}
							}

							stopwatch.Stop();
							Global.OnProcess?.Invoke($"The API Gateway Services Controller is{(this.State == ServiceState.Disconnected ? " re-" : " ")}started successful - Execution times: {stopwatch.GetElapsedTimes()}");
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
							WAMPConnections.IncommingChannel.ReOpen(this._cancellationTokenSource.Token, Global.OnError, "Incomming");
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
					},
					(sender, arguments) =>
					{
						if (WAMPConnections.ChannelsAreClosedBySystem || arguments.CloseType.Equals(SessionCloseType.Goodbye))
							Global.OnProcess?.Invoke($"The outgoing channel is closed - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");

						else
						{
							Global.OnProcess?.Invoke($"The outgoing channel to WAMP router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
							WAMPConnections.OutgoingChannel.ReOpen(this._cancellationTokenSource.Token, Global.OnError, "Outgoing");
						}
					},
					(sender, arguments) =>
					{
						Global.OnError?.Invoke($"The outgoging channel to WAMP router got an error: {arguments.Exception.Message}", arguments.Exception);
					}
				)
			}, this._cancellationTokenSource.Token);
		}

		public void Stop()
		{
			MailSender.SaveMessages();
			WebHookSender.SaveMessages();

			this._timers.ForEach(timer => timer.Dispose());
			this._tasks.Values.ForEach(serviceInfo => ExternalProcess.Stop(serviceInfo.Instance));
			this._businessServices.Keys.ToList().ForEach(name => this.StopBusinessService(name, () => Global.OnProcess?.Invoke($"[{name.ToLower()}] => The service is stopped")));

			this._communicator?.Dispose();
			this._loggingService?.FlushAllLogs();

			this._helperServices.ForEach(async (service) => await service.DisposeAsync().ConfigureAwait(false));
			this._cancellationTokenSource.Cancel();

			WAMPConnections.CloseChannels();

			this.State = ServiceState.Disconnected;
		}
		#endregion

		#region Start/Stop business service
		public Dictionary<string, string> GetAvailableBusinessServices()
			=> this._businessServices.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Executable);

		public bool IsBusinessServiceRunning(string name)
			=> !string.IsNullOrWhiteSpace(name) && this._businessServices.TryGetValue(name.Trim().ToLower(), out ServiceInfo info)
				? info.Instance != null
				: false;

		Tuple<string, string> PrepareServiceHosting(string name)
		{
			var serviceInfo = this._businessServices[name];
			serviceInfo.Extra.TryGetValue("Bitness", out string bitness);
			var serviceHosting = !string.IsNullOrWhiteSpace(serviceInfo.Executable)
					? serviceInfo.Executable
					: "x86".IsEquals(bitness) || "32bits".IsEquals(bitness) ? this._serviceHosting_x86 : this._serviceHosting;
			if (serviceHosting.IndexOf(Path.DirectorySeparatorChar) < 0)
				serviceHosting = this._workingDirectory + serviceHosting;
			return new Tuple<string, string>(serviceHosting, serviceInfo.Arguments);
		}

		public void StartBusinessService(string name, string arguments = null)
		{
			if (this.IsBusinessServiceRunning(name))
				return;

			name = name.Trim().ToLower();
			Global.OnProcess?.Invoke($"[{name}] => The service is starting");
			try
			{
				var serviceInfo = this.PrepareServiceHosting(name);
				var serviceHosting = serviceInfo.Item1;
				var serviceType = serviceInfo.Item2;

				if (!File.Exists(serviceHosting + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "")))
					throw new FileNotFoundException($"The service hosting is not found [{serviceHosting + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "")}]");

				this._businessServices[name].Instance = ExternalProcess.Start(
					serviceHosting,
					$"/agc:r /svc:{serviceType} {arguments ?? ""}".Trim(),
					(sender, args) =>
					{
						this._businessServices[name].Instance = null;
						Global.OnServiceStopped?.Invoke(name, $"The sevice is stopped");
					},
					(sender, args) => Global.OnGotServiceMessage?.Invoke(name, args.Data)
				);
				Global.OnServiceStarted?.Invoke(name, $"The service is started - Process ID: {this._businessServices[name].Instance.ID} [{serviceHosting} {$"/agc:r /svc:{serviceType} {arguments ?? ""}".Trim()}]");
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"[{name}] => Cannot start the service: {ex.Message}", ex is FileNotFoundException ? null : ex);
			}
		}

		public void StopBusinessService(string name)
		{
			if (!this.IsBusinessServiceRunning(name))
				return;

			name = name.Trim().ToLower();
			Global.OnProcess?.Invoke($"[{name}] => The service is stopping");
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				try
				{
					var serviceInfo = this.PrepareServiceHosting(name);
					var serviceHosting = serviceInfo.Item1;
					var serviceType = serviceInfo.Item2;
					var processInfo = ExternalProcess.Start(serviceHosting, $"/agc:s /svc:{serviceType}", "");
					processInfo.Process.Dispose();
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while stopping the service [{name}] => {ex.Message}", ex);
				}
			else
				ExternalProcess.Stop(this._businessServices[name].Instance, info => { }, ex => Global.OnError?.Invoke($"Error occurred while stopping the service [{name}] => {ex.Message}", ex));
		}

		internal void StopBusinessService(string name, Action onStopped = null)
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
				this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(this, new RegistrationInterceptor(null, new RegisterOptions() { Invoke = WampInvokePolicy.Single })).ConfigureAwait(false));
				Global.OnProcess?.Invoke($"The centralized managing service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");
			}
			catch (WampSessionNotEstablishedException)
			{
				throw;
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Error occurred while{(this.State == ServiceState.Disconnected ? " re-" : " ")}registering the centralized managing service: {ex.Message}", ex);
			}

			this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(this._loggingService, RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.OnProcess?.Invoke($"The centralized logging service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");

			this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(new MessagingService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.OnProcess?.Invoke($"The centralized messaging service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");

			this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(new RTUService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.OnProcess?.Invoke($"The real-time update (RTU) service is{(this.State == ServiceState.Disconnected ? " re-" : " ")}registered");
		}
		#endregion

		#region Register timers for working with background workers & schedulers
		IDisposable StartTimer(Action action, int interval, int delay = 0)
		{
			interval = interval < 1 ? 1 : interval;
			var timer = Observable.Timer(TimeSpan.FromMilliseconds(delay > 0 ? delay : interval * 1000), TimeSpan.FromSeconds(interval)).Subscribe(_ => action?.Invoke());
			this._timers.Add(timer);
			return timer;
		}

		void RegisterMessagingTimers()
		{
			// send email messages (15 seconds)
			this.StartTimer(async () =>
			{
				if (this._mailSender == null)
					try
					{
						this._mailSender = new MailSender(this._cancellationTokenSource.Token);
						await this._mailSender.ProcessAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError.Invoke($"Error occurred while sending web-hook messages: {ex.Message}", ex);
					}
					finally
					{
						this._mailSender = null;
					}
			}, 15);

			// send web hook messages (35 seconds)
			this.StartTimer(async () =>
			{
				if (this._webhookSender == null)
					try
					{
						this._webhookSender = new WebHookSender(this._cancellationTokenSource.Token);
						await this._webhookSender.ProcessAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.OnError.Invoke($"Error occurred while sending web-hook messages: {ex.Message}", ex);
					}
					finally
					{
						this._webhookSender = null;
					}
			}, 35);
		}

		void RegisterSchedulingTimers()
		{
			// flush logs (DEBUG: 5 seconds - Other: 1 minute)
			this.StartTimer(() =>
			{
				this._loggingService?.FlushAllLogs();
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
			if (this._isHouseKeeperRunning)
				return;

			// prepare
			this._isHouseKeeperRunning = true;
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
			this._isHouseKeeperRunning = false;
		}

		void PrepareRecycleBin()
		{
			var connectionStrings = new Dictionary<string, string>();
			var dataSources = new Dictionary<string, XmlNode>();
			var dbProviderFactories = new Dictionary<string, XmlNode>();

			new List<string>
			{
				this._serviceHosting + $".{(this._isNETFramework ? "exe" : "dll")}.config",
				this._serviceHosting + $".{(this._isNETFramework ? "exe" : "dll")}.x86.config"
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

			Global.OnProcess?.Invoke("Construct database provider factories");
			RepositoryStarter.ConstructDbProviderFactories(dbProviderFactories.Values.ToList(), (msg, ex) =>
			{
				if (ex != null)
					Global.OnError?.Invoke(msg, ex);
				else
					Global.OnProcess?.Invoke(msg);
			});

			Global.OnProcess?.Invoke("Construct data sources");
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
				this._serviceHosting + $".{(this._isNETFramework ? "exe" : "dll")}.config",
				this._serviceHosting + $".{(this._isNETFramework ? "exe" : "dll")}.x86.config"
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
			if (this._isTaskSchedulerRunning)
				return;

			// prepare
			var tasks = this._tasks.Values
				.Where(serviceInfo => serviceInfo.Instance == null && ("hourly".IsEquals(serviceInfo.Extra["Time"]) || $"{DateTime.Now.Hour}".IsEquals(serviceInfo.Extra["Time"])))
				.ToList();

			if (tasks.Count < 1)
				return;

			// start
			this._isTaskSchedulerRunning = true;
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
					this._tasks[task.ID].Instance = ExternalProcess.Start(
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
							this._tasks[task.ID].Instance = null;
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
						await Task.Delay(1234, this._cancellationTokenSource.Token).ConfigureAwait(false);
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
			this._isTaskSchedulerRunning = false;
		}
		#endregion

		#region Process inter-communicate messages
		Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
			=> Task.CompletedTask;
		#endregion

		#region Dispose
		public void Dispose()
		{
			if (!this._disposed)
			{
				this._disposed = true;
				this.Stop();
				this._cancellationTokenSource.Dispose();
				GC.SuppressFinalize(this);
			}
		}

		~Controller()
		{
			this.Dispose();
		}
		#endregion

	}

	#region Service information
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