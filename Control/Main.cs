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
			this._serviceHosting = UtilityService.GetAppSetting("ServiceHosting", "VIEApps.Services.APIGateway.Hosting").Trim();
			if (this._serviceHosting.IsEndsWith(".exe") || this._serviceHosting.IsEndsWith(".dll"))
				this._serviceHosting = this._serviceHosting.Left(this._serviceHosting.Length - 4).Trim();
		}

		#region Attributes
		public string Status { get; private set; } = "Initializing";
		readonly CancellationTokenSource _cancellationTokenSource;
		internal IDisposable _communicator = null;
		readonly internal LoggingService _loggingService = null;
		readonly string _serviceHosting;
		internal Dictionary<string, string> _availableServices = null;
		readonly Dictionary<string, ExternalProcess.Info> _runningServices = new Dictionary<string, ExternalProcess.Info>();
		readonly List<SystemEx.IAsyncDisposable> _helperServices = new List<SystemEx.IAsyncDisposable>();
		readonly List<IDisposable> _timers = new List<IDisposable>();
		MailSender _mailSender = null;
		WebHookSender _webhookSender = null;
		bool _isHouseKeeperRunning = false, _isTaskSchedulerRunning = false;
		readonly Dictionary<string, Tuple<string, string, string>> _tasks = new Dictionary<string, Tuple<string, string, string>>();
		readonly List<Tuple<int, string>> _runningTasks = new List<Tuple<int, string>>();
		readonly bool _isNETFramework = RuntimeInformation.FrameworkDescription.IsContains(".NET Framework");
		readonly string _workingDirectory = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar.ToString();
		bool _registerHelperServices = true, _registerBusinessServices = true, _registerTimers = true, _disposed = false;
		#endregion

		#region Start/Stop
		public void Start(string[] args = null, Func<Task> nextAsync = null)
		{
			// prepare arguments
#if !DEBUG
				if (Environment.UserInteractive)
				{
					this._registerHelperServices = this._registerBusinessServices = this._registerTimers = false;
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
#endif

			// register helper & start business services
			async Task registerServicesAsync()
			{
				// register helper services
				if (this._registerHelperServices)
					await this.RegisterHelperServicesAsync().ConfigureAwait(false);

				// update status
				this.Status = "Ready";

				// register timers
				if (this._registerTimers)
					try
					{
						this.RegisterMessagingTimers();
						this.RegisterSchedulingTimers();
						Global.OnProcess?.Invoke("The background workers & schedulers are registered");
					}
					catch (Exception ex)
					{
						Global.OnError?.Invoke("Error occurred while registering background workers & schedulers", ex);
					}
			}

			// connect to WAMP router to open channels
			async Task openChannelsAsync()
			{
				var routerInfo = WAMPConnections.GetRouterInfo();
				Global.OnProcess?.Invoke($"Attempting to connect to WAMP router [{routerInfo.Item1}{(routerInfo.Item1.EndsWith("/") ? "" : "/")}{routerInfo.Item2}]");

				await Task.WhenAll(
					WAMPConnections.OpenIncomingChannelAsync(
						(sender, arguments) =>
						{
							Global.OnProcess?.Invoke($"The incoming channel is established - Session ID: {arguments.SessionId}");
							this._communicator = WAMPConnections.IncommingChannel.RealmProxy.Services
								.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
								.Subscribe(
									async (message) => await this.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false),
									exception => Global.OnError?.Invoke("Error occurred while fetching inter-communicate message", exception)
								);
							Global.OnProcess?.Invoke($"The inter-communicate message updater is started");
						},
						(sender, arguments) =>
						{
							if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
								Global.OnProcess?.Invoke($"The incoming channel is broken because the router is not found or the router is refused - Session ID: {arguments.SessionId} - Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}");
							else
							{
								if (WAMPConnections.ChannelsAreClosedBySystem)
									Global.OnProcess?.Invoke($"The incoming channel is closed - Session ID: {arguments.SessionId} - Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}");
								else
									WAMPConnections.IncommingChannel.ReOpenChannel(
										channel => Global.OnProcess?.Invoke("Re-connect the incoming channel successful"),
										ex => Global.OnError?.Invoke("Error occurred while re-connecting the incoming channel", ex),
										this._cancellationTokenSource.Token
									);
							}
						},
						(sender, arguments) =>
						{
							Global.OnError?.Invoke($"Got an error of incoming channel [{(arguments.Exception != null ? arguments.Exception.Message : "None")}", arguments.Exception);
						}
					),
					WAMPConnections.OpenOutgoingChannelAsync(
						(sender, arguments) =>
						{
							Global.OnProcess?.Invoke($"The outgoing channel is established - Session ID: {arguments.SessionId}");
							Task.Run(async () => await registerServicesAsync().ConfigureAwait(false))
								.ContinueWith(async (task) =>
								{
									await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
									Global.OnProcess?.Invoke($"The API Gateway Services Controller is started");
									if (this._registerBusinessServices)
										this.RegisterBusinessServices();
								}, TaskContinuationOptions.OnlyOnRanToCompletion)
								.ContinueWith(async (task) =>
								{
									if (nextAsync != null)
										try
										{
											await nextAsync().ConfigureAwait(false);
										}
										catch (Exception ex)
										{
											Global.OnError?.Invoke($"Error occurred while invoking the next action: {ex.Message}", ex);
										}
								}, TaskContinuationOptions.OnlyOnRanToCompletion)
								.ConfigureAwait(false);
						},
						(sender, arguments) =>
						{
							if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
								Global.OnProcess?.Invoke($"The outgoing channel is broken because the router is not found or the router is refused - Session ID: {arguments.SessionId} - Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}");
							else
							{
								if (WAMPConnections.ChannelsAreClosedBySystem)
									Global.OnProcess?.Invoke($"The outgoing channel is closed - Session ID: {arguments.SessionId} - Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}");
								else
									WAMPConnections.OutgoingChannel.ReOpenChannel(
										channel => Global.OnProcess?.Invoke("Re-connect the outgoing channel successful"),
										ex => Global.OnError?.Invoke("Error occurred while re-connecting the outgoing channel", ex),
										this._cancellationTokenSource.Token
									);
							}
						},
						(sender, arguments) =>
						{
							Global.OnError?.Invoke($"Got an error of outgoing channel [{(arguments.Exception != null ? arguments.Exception.Message : "None")}", arguments.Exception);
						}
					)
				).ConfigureAwait(false);
			}

			// run start			
			Task.Run(() =>
			{
				Global.OnProcess?.Invoke("The API Gateway Services Controller is starting");
				Global.OnProcess?.Invoke($"Version: {typeof(Controller).Assembly.GetVersion()}");
				Global.OnProcess?.Invoke($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : $"Other OS")} {RuntimeInformation.OSArchitecture} ({RuntimeInformation.OSDescription.Trim()})");
#if DEBUG
				Global.OnProcess?.Invoke($"Working mode: {(Environment.UserInteractive ? "Console App" : "Daemon")} (DEBUG) - Directory: {this._workingDirectory}");
#else
				Global.OnProcess?.Invoke($"Working mode: {(Environment.UserInteractive ? "Console App" : "Daemon")} (RELEASE) - Directory: {this._workingDirectory}");
#endif

				(Global.StatusPath + "," + LoggingService.LogsPath + "," + MailSender.EmailsPath + "," + WebHookSender.WebHooksPath)
					.ToArray()
					.Where(path => !Directory.Exists(path))
					.ForEach(path => Directory.CreateDirectory(path));
			})
			.ContinueWith(async (task) =>
			{
				await openChannelsAsync().ConfigureAwait(false);
			}, TaskContinuationOptions.OnlyOnRanToCompletion)
			.ConfigureAwait(false);
		}

		public void Stop()
		{
			MailSender.SaveMessages();
			WebHookSender.SaveMessages();

			this._timers.ForEach(timer => timer.Dispose());
			this._runningTasks.Select(s => s.Item1).ToList().ForEach(pid => ExternalProcess.Kill(pid));
			this._runningServices.Keys.ToList().ForEach(name => this.StopBusinessService(name));

			this._communicator?.Dispose();
			this._loggingService?.FlushAllLogs();

			this._helperServices.ForEach(async (s) => await s.DisposeAsync().ConfigureAwait(false));
			this._cancellationTokenSource.Cancel();

			WAMPConnections.CloseChannels();
		}
		#endregion

		#region Start/Stop business service
		void RegisterBusinessServices()
		{
			// get services
			this.GetAvailableBusinessServices();

			// start all services
			var serviceHosting = $"{this._workingDirectory}{this._serviceHosting}{(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "")}";
			if (File.Exists(serviceHosting))
				foreach (var kvp in this._availableServices)
					Task.Run(async () =>
					{
						await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
						this.StartBusinessService(kvp.Key);
					}).ConfigureAwait(false);
			else
				Global.OnError?.Invoke($"The service hosting [{serviceHosting}] is not found", null);
		}

		public Dictionary<string, string> GetAvailableBusinessServices()
		{
			if (this._availableServices == null)
			{
				this._availableServices = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
				if (ConfigurationManager.GetSection("net.vieapps.services") is AppConfigurationSectionHandler config)
					if (config.Section.SelectNodes("./add") is XmlNodeList services)
						services.ToList().ForEach(service =>
						{
							var name = service.Attributes["name"]?.Value;
							var type = service.Attributes["type"]?.Value;
							if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(type))
								this._availableServices[name.ToLower().Trim()] = type.Trim().Replace(" ", "");
						});
			}
			return this._availableServices;
		}

		public bool IsBusinessServiceRunning(string name)
			=> !string.IsNullOrWhiteSpace(name)
				? this._runningServices.ContainsKey(name.Trim().ToLower())
				: false;

		public void StartBusinessService(string name, string arguments = null)
		{
			if (string.IsNullOrWhiteSpace(name) || !this._availableServices.ContainsKey(name.Trim().ToLower()) || this._runningServices.ContainsKey(name.Trim().ToLower()))
				return;

			name = name.Trim().ToLower();
			Global.OnProcess?.Invoke($"[{name}] => The service is starting...");
			try
			{
				var serviceHosting = $"{this._workingDirectory}{this._serviceHosting}";
				var serviceType = this._availableServices[name];

				if (serviceType.IsEndsWith(",x86"))
				{
					serviceHosting += ".x86";
					serviceType = serviceType.Left(serviceType.Length - 4);
				}

				this._runningServices[name] = ExternalProcess.Start(
					serviceHosting,
					$"{arguments ?? ""} /agc:{(Environment.UserInteractive ? "g" : "r")} /svc:{serviceType}".Trim(),
					(sender, args) =>
					{
						this._runningServices.Remove(name);
						Global.OnServiceStopped?.Invoke(name, "The sevice is stopped...");
					},
					(sender, args) => Global.OnGotServiceMessage?.Invoke(name, args.Data)
				);
				Global.OnServiceStarted?.Invoke(name, $"The service is started - Process ID: {this._runningServices[name].ID}");
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke($"Cannot start the service [{name}] => {ex.Message}", ex);
			}
		}

		public void StopBusinessService(string name)
		{
			if (string.IsNullOrWhiteSpace(name) || !this._runningServices.ContainsKey(name.Trim().ToLower()))
				return;

			name = name.Trim().ToLower();
			Global.OnProcess?.Invoke($"[{name}] => The service is stopping...");
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				try
				{
					var serviceHosting = $"{this._workingDirectory}{this._serviceHosting}";
					var serviceType = this._availableServices[name];

					if (serviceType.IsEndsWith(",x86"))
					{
						serviceHosting += ".x86";
						serviceType = serviceType.Left(serviceType.Length - 4);
					}

					var info = ExternalProcess.Start(serviceHosting, $"/agc:s /svc:{serviceType}", (sender, args) => this._runningServices.Remove(name), null);
					info.Process.Dispose();
				}
				catch (Exception ex)
				{
					Global.OnError?.Invoke($"Error occurred while stopping the service [{name}] => {ex.Message}", ex);
				}
			else
				ExternalProcess.Stop(this._runningServices[name], info => this._runningServices.Remove(name), ex => Global.OnError?.Invoke($"Error occurred while stopping the service [{name}] => {ex.Message}", ex));
		}
		#endregion

		#region Register helper services
		async Task RegisterHelperServicesAsync()
		{
			try
			{
				this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(this, new RegistrationInterceptor(null, new RegisterOptions() { Invoke = WampInvokePolicy.Single })).ConfigureAwait(false));
				Global.OnProcess?.Invoke("The centralized managing service is registered");
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke("Error occurred while registering the centralized managing service", ex);
			}

			try
			{
				this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(this._loggingService, RegistrationInterceptor.Create()).ConfigureAwait(false));
				Global.OnProcess?.Invoke("The centralized logging service is registered");
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke("Error occurred while registering the centralized logging service", ex);
			}

			try
			{
				this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(new MessagingService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
				Global.OnProcess?.Invoke("The centralized messaging service is registered");
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke("Error occurred while registering the centralized messaging service", ex);
			}

			try
			{
				this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(new RTUService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
				Global.OnProcess?.Invoke("The real-time update (RTU) service is registered");
			}
			catch (Exception ex)
			{
				Global.OnError?.Invoke("Error occurred while registering the real-time update (RTU) service", ex);
			}
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
				{
					this._mailSender = new MailSender(this._cancellationTokenSource.Token);
					try
					{
						await this._mailSender.ProcessAsync().ConfigureAwait(false);
					}
					catch { }
					finally
					{
						this._mailSender = null;
					}
				}
			}, 15);

			// send web hook messages (35 seconds)
			this.StartTimer(async () =>
			{
				if (this._webhookSender == null)
				{
					this._webhookSender = new WebHookSender(this._cancellationTokenSource.Token);
					try
					{
						await this._webhookSender.ProcessAsync().ConfigureAwait(false);
					}
					catch { }
					finally
					{
						this._webhookSender = null;
					}
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
			this.StartTimer(() =>
			{
				this.RunHouseKeeper();
			}, 60 * 60);

			// task scheduler (hourly)
			var runTaskSchedulerOnFirstLoad = false;
			if (ConfigurationManager.GetSection("net.vieapps.task.scheduler") is AppConfigurationSectionHandler config)
			{
				runTaskSchedulerOnFirstLoad = "true".IsEquals(config.Section.Attributes["runOnFirstLoad"]?.Value);
				if (config.Section.SelectNodes("task") is XmlNodeList taskNodes)
					foreach (XmlNode taskNode in taskNodes)
					{
						if (string.IsNullOrWhiteSpace(taskNode.Attributes["execute"]?.Value) || !File.Exists(taskNode.Attributes["execute"].Value))
							continue;

						var info = new Tuple<string, string, string>(
							taskNode.Attributes["execute"].Value.Trim(),
							(taskNode.Attributes["arguments"]?.Value ?? "").Trim(),
							taskNode.Attributes["time"]?.Value ?? "3"
						);

						var identity = $"{info.Item1}[{info.Item2}]".ToLower().GetMD5();
						if (!this._tasks.ContainsKey(identity))
							this._tasks.Add(identity, info);
					}
			}

			this.StartTimer(async () =>
			{
				await this.RunTaskSchedulerAsync().ConfigureAwait(false);
			}, 65 * 60, runTaskSchedulerOnFirstLoad ? 5678 : 0);
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

			var filenames = new List<string>
			{
				this._serviceHosting + $".{(this._isNETFramework ? "exe" : "dll")}.config"
			};
			filenames.Add(filenames[0].Replace(".config", ".x86.config"));
			filenames.Where(filename => File.Exists(filename)).ForEach(filename =>
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

			var filenames = new List<string>
			{
				this._serviceHosting + $".{(this._isNETFramework ? "exe" : "dll")}.config"
			};
			filenames.Add(filenames[0].Replace(".config", ".x86.config"));
			filenames.Where(filename => File.Exists(filename)).ForEach(filename =>
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
			var tasks = this._tasks.Where(task => this._runningTasks.FirstOrDefault(info => info.Item2.Equals(task.Key)) == null ? task.Value.Item3.IsEquals("hourly") || task.Value.Item3.Equals(DateTime.Now.Hour.ToString()) : false).ToList();
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
					this._runningTasks.Add(new Tuple<int, string>(ExternalProcess.Start(
						task.Value.Item1,
						task.Value.Item2,
						(sender, args) =>
						{
							var command = task.Value.Item1 + " " + task.Value.Item2;
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
							this._runningTasks.Remove(this._runningTasks.First(info => info.Item1 == (sender as Process).Id));
							running = false;
						},
						(sender, args) => results += string.IsNullOrWhiteSpace(args.Data) ? "" : $"\r\n{args.Data}"
					).ID.Value, task.Key));
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
						ExternalProcess.Kill(this._runningTasks.First(t => t.Item2 == task.Key).Item1);
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

}