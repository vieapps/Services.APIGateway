﻿#region Related components
using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Diagnostics;
using System.Configuration;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Reactive.Linq;

using Microsoft.Extensions.Logging;

using WampSharp.V2;
using WampSharp.V2.Rpc;
using WampSharp.V2.Core.Contracts;
using WampSharp.V2.Realm;
using WampSharp.Core.Listener;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class ControlComponent : IServiceManager, IDisposable
	{

		public ControlComponent(CancellationToken cancellationToken = default(CancellationToken))
		{
			this._cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			this._loggingService = new LoggingService(this._cancellationTokenSource.Token);
		}

		#region Attributes
		public string Status { get; private set; } = "Initializing";
		readonly CancellationTokenSource _cancellationTokenSource;
		internal IDisposable _communicator = null;
		readonly internal LoggingService _loggingService = null;
		readonly string _serviceHoster = UtilityService.GetAppSetting("ServiceHoster", "VIEApps.Services.APIGateway.Host.exe");
		internal Dictionary<string, string> _availableServices = null;
		readonly Dictionary<string, int> _runningServices = new Dictionary<string, int>();
		readonly List<SystemEx.IAsyncDisposable> _helperServices = new List<SystemEx.IAsyncDisposable>();
		readonly List<IDisposable> _timers = new List<IDisposable>();
		MailSender _mailSender = null;
		WebHookSender _webhookSender = null;
		bool _isHouseKeeperRunning = false, _isTaskSchedulerRunning = false;
		readonly Dictionary<string, Tuple<string, string, string>> _tasks = new Dictionary<string, Tuple<string, string, string>>();
		readonly List<Tuple<int, string>> _runningTasks = new List<Tuple<int, string>>();

		bool _registerHelperServices = true, _registerBusinessServices = true, _registerTimers = true;
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

				// call service to update status
				else
					this.Status = "Ready";

				// register timers
				if (this._registerTimers)
				{
					this.RegisterMessagingTimers();
					this.RegisterSchedulingTimers();
					Global.OnProcess("The background workers & schedulers are registered");
				}
			}

			// connect to WAMP router to open channels
			async Task openChannelsAsync()
			{
				var info = WAMPConnections.GetRouterInfo();
				Global.OnProcess($"Attempting to connect to WAMP router [{info.Item1}{info.Item2}]");

				await Task.WhenAll(
					WAMPConnections.OpenIncomingChannelAsync(
						(sender, arguments) =>
						{
							Global.OnProcess($"The incoming connection is established - Session ID: {arguments.SessionId}");
							this._communicator = WAMPConnections.IncommingChannel.RealmProxy.Services
								.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
								.Subscribe(
									async (message) => await this.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false),
									exception => Global.OnError("Error occurred while fetching inter-communicate message", exception)
								);
							Global.OnProcess($"The inter-communicate message updater is started");
						},
						(sender, arguments) =>
						{
							if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
								Global.OnProcess($"The incoming connection is broken because the router is not found or the router is refused - Session ID: {arguments.SessionId} - Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}");
							else
							{
								if (WAMPConnections.ChannelsAreClosedBySystem)
									Global.OnProcess($"The incoming connection is closed - Session ID: {arguments.SessionId}- Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}");
								else
									WAMPConnections.IncommingChannel.ReOpen(
										(channel) => Global.OnProcess("Re-connect the incoming connection successful"),
										ex => Global.OnError("Error occurred while re-connecting the incoming connection", ex)
									);
							}
						},
						(sender, arguments) =>
						{
							Global.OnError($"Got an error of incoming connection [{(arguments.Exception != null ? arguments.Exception.Message : "None")}", arguments.Exception);
						}
					),
					WAMPConnections.OpenOutgoingChannelAsync(
						(sender, arguments) =>
						{
							Global.OnProcess($"The outgoing connection is established - Session ID: {arguments.SessionId}");
							Task.Run(async () => await registerServicesAsync().ConfigureAwait(false))
								.ContinueWith(async (task) =>
								{
									await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);
									Global.OnProcess($"The API Gateway Services Controller is started");
									if (this._registerBusinessServices)
										this.RegisterBusinessServices();
								}, TaskContinuationOptions.OnlyOnRanToCompletion)
								.ConfigureAwait(false);
						},
						(sender, arguments) =>
						{
							if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
								Global.OnProcess($"The outgoing connection is broken because the router is not found or the router is refused - Session ID: {arguments.SessionId} - Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}");
							else
							{
								if (WAMPConnections.ChannelsAreClosedBySystem)
									Global.OnProcess($"The outgoing connection is closed - Session ID: {arguments.SessionId} - Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}");
								else
									WAMPConnections.OutgoingChannel.ReOpen(
										(channel) => Global.OnProcess("Re-connect the outgoing connection successful"),
										ex => Global.OnError("Error occurred while re-connecting the outgoing connection", ex)
									);
							}
						},
						(sender, arguments) =>
						{
							Global.OnError($"Got an error of outgoing connection [{(arguments.Exception != null ? arguments.Exception.Message : "None")}", arguments.Exception);
						}
					)
				).ConfigureAwait(false);
			}

			// run start			
			Task.Run(() =>
			{
				Global.OnProcess($"The API Gateway Services Controller is starting");
				(Global.StatusPath + "," + LoggingService.LogsPath + "," + MailSender.EmailsPath + "," + WebHookSender.WebHooksPath)
					.ToArray()
					.Where(path => !Directory.Exists(path))
					.ForEach(path => Directory.CreateDirectory(path));
			})
			.ContinueWith(async (task) =>
			{
				await openChannelsAsync().ConfigureAwait(false);
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
						Global.OnError("Error occurred while invoking the next action", ex);
					}
			}, TaskContinuationOptions.OnlyOnRanToCompletion)
			.ConfigureAwait(false);
		}

		public void Stop()
		{
			MailSender.SaveMessages();
			WebHookSender.SaveMessages();

			this._timers.ForEach(timer => timer.Dispose());
			this._runningTasks.Select(s => s.Item1).ToList().ForEach(pid => this.KillProcess(pid));
			this._runningServices.Select(kvp => kvp.Key).ToList().ForEach(name => this.StopBusinessService(name, false));

			this._communicator?.Dispose();
			this._loggingService?.FlushAllLogs();

			this._helperServices.ForEach(async (s) => await s.DisposeAsync().ConfigureAwait(false));

			WAMPConnections.CloseChannels();
			this._cancellationTokenSource.Cancel();
		}
		#endregion

		#region Start/Stop business service
		void RegisterBusinessServices()
		{
			// get services
			this.GetAvailableBusinessServices();

			// start all services
			if (File.Exists(this._serviceHoster))
				this._availableServices.ForEach(kvp => this.StartBusinessService(kvp.Key));
			else
				Global.OnError($"The service hoster [{this._serviceHoster}] is not found", null);
		}

		public Dictionary<string, string> GetAvailableBusinessServices()
		{
			if (this._availableServices == null)
			{
				this._availableServices = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
				if (ConfigurationManager.GetSection("net.vieapps.services") is AppConfigurationSectionHandler config)
					if (config.Section.SelectNodes("./add") is XmlNodeList services)
						foreach (XmlNode service in services)
						{
							var name = service.Attributes["name"]?.Value;
							var type = service.Attributes["type"]?.Value;
							if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(type))
								this._availableServices[name.ToLower().Trim()] = type.Trim().Replace(" ", "");
						}
			}
			return this._availableServices;
		}

		public bool IsBusinessServiceRunning(string name)
		{
			return !string.IsNullOrWhiteSpace(name)
				? this._runningServices.ContainsKey(name.Trim().ToLower())
				: false;
		}

		public void StartBusinessService(string name, string arguments = null)
		{
			if (string.IsNullOrWhiteSpace(name) || !this._availableServices.ContainsKey(name.ToLower()) || this._runningServices.ContainsKey(name.ToLower()))
				return;

			var serviceHoster = this._serviceHoster;
			var serviceType = this._availableServices[name.ToLower()];
			if (serviceType.IsEndsWith(",x86"))
			{
				serviceHoster = serviceHoster.Replace(StringComparison.OrdinalIgnoreCase, ".exe", ".x86.exe");
				serviceType = serviceType.Left(serviceType.Length - 4);
			}
			var serviceArguments = (arguments ?? "") + $" /agc:{(Environment.UserInteractive ? "g" : "r")} /svc:{serviceType} /svn:{name.ToLower()}";

			Global.OnProcess($"The service [{name.ToLower()}] is starting...");
			var process = UtilityService.RunProcess(
				serviceHoster,
				serviceArguments,
				(sender, args) =>
				{
					try
					{
						var serviceName = (sender as Process).StartInfo.Arguments.Split(' ').FirstOrDefault(a => a.IsStartsWith("/svn:"));
						if (!string.IsNullOrWhiteSpace(serviceName))
						{
							this._runningServices.Remove(serviceName.ToLower().Replace("/svn:", ""));
							Global.OnServiceStopped(serviceName, "The sevice is stopped...");
						}
					}
					catch (Exception ex)
					{
						Global.OnError($"Error while running service: {ex.Message}", ex);
					}
				},
				(sender, args) =>
				{
					var serviceName = (sender as Process).StartInfo.Arguments.Split(' ').FirstOrDefault(a => a.IsStartsWith("/svn:"));
					if (!string.IsNullOrWhiteSpace(serviceName) && !string.IsNullOrWhiteSpace(args.Data))
						Global.OnGotServiceMessage(serviceName, args.Data);
				}
			);

			this._runningServices[name.ToLower()] = process.Id;
			Global.OnServiceStarted(name, $"The service [{name.ToLower()}] is started - PID: {process.Id}");
		}

		public void StopBusinessService(string name, bool updateStatus = true)
		{
			if (!string.IsNullOrWhiteSpace(name) && this._runningServices.ContainsKey(name.ToLower()))
				try
				{
					// stop the service
					var processID = this._runningServices[name.ToLower()];
					var serviceHoster = this._serviceHoster;
					var serviceType = this._availableServices[name.ToLower()];
					if (serviceType.IsEndsWith(",x86"))
					{
						serviceHoster = serviceHoster.IsEndsWith(".exe")
							? serviceHoster.Replace(StringComparison.OrdinalIgnoreCase, ".exe", ".x86.exe")
							: serviceHoster + ".x86";
						serviceType = serviceType.Left(serviceType.Length - 4);
					}
					var serviceArguments = $"/agc:s /svc:{serviceType} /svn:{name.ToLower()}";
					UtilityService.RunProcess(serviceHoster, serviceArguments, (sender, args) => this.KillProcess(processID));

					// update status
					if (updateStatus)
						this._runningServices.Remove(name.ToLower());
				}
				catch { }
		}

		void KillProcess(int processID)
		{
			try
			{
				UtilityService.KillProcess(processID);
			}
			catch { }
		}
		#endregion

		#region Register helper services
		async Task RegisterHelperServicesAsync()
		{
			try
			{
				this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(this, new RegistrationInterceptor(null, new RegisterOptions() { Invoke = WampInvokePolicy.Single })).ConfigureAwait(false));
				Global.OnProcess("The centralized managing service is registered");
			}
			catch (Exception ex)
			{
				Global.OnError("Error occurred while registering the centralized managing service", ex);
			}

			this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(this._loggingService, RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.OnProcess("The centralized logging service is registered");

			this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(new MessagingService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.OnProcess("The centralized messaging service is registered");

			this._helperServices.Add(await WAMPConnections.IncommingChannel.RealmProxy.Services.RegisterCallee(new RTUService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.OnProcess("The real-time update (RTU) service is registered");

			this.Status = "Ready";
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
			var stopwatch = new Stopwatch();
			stopwatch.Start();

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
			paths.Select(path => new DirectoryInfo(path))
				.Where(dir => dir.Exists)
				.ForEach(dir =>
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
			UtilityService.GetFiles(LoggingService.LogsPath, "*.*")
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

			// clean recycle-bin contents
			var logs = this.CleanRecycleBin();

			// done
			stopwatch.Stop();
			Global.OnProcess(
				"The house keeper is complete the working..." + "\r\n\r\nPaths\r\n=> " + paths.ToString("\r\n=> ") + "\r\n\r\n" +
				"Total of cleaned files: " + counter.ToString("###,##0") + "\r\n\r\n" +
				"Recycle-Bin\r\n\t" + logs.ToString("\r\n\t") + "\r\n\r\n" +
				"Execution times: " + stopwatch.GetElapsedTimes()
			);
			this._isHouseKeeperRunning = false;
		}

		void PrepareRecycleBin()
		{
			var connectionStrings = new Dictionary<string, string>();
			$"{this._serviceHoster}.config|{this._serviceHoster.Replace(".exe", ".x86.exe")}.config".ToList("|")
				.Where(filename => File.Exists(filename))
				.ForEach(filename =>
				{
					var xml = new XmlDocument();
					xml.LoadXml(UtilityService.ReadTextFile(filename));

					if (xml.DocumentElement.SelectNodes("/configuration/connectionStrings/add") is XmlNodeList connectionStringNodes)
						foreach (XmlNode connectionStringNode in connectionStringNodes)
						{
							var name = connectionStringNode.Attributes["name"]?.Value;
							var connectionString = connectionStringNode.Attributes["connectionString"]?.Value;
							if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(connectionString) && !connectionStrings.ContainsKey(name))
								connectionStrings[name] = connectionString;
						}

					if (xml.DocumentElement.SelectNodes("/configuration/net.vieapps.repositories/dataSources/dataSource") is XmlNodeList dataSourceNodes)
					{
						Global.OnProcess("Construct data sources");
						foreach (XmlNode dataSourceNode in dataSourceNodes)
						{
							var connectionStringName = dataSourceNode.Attributes["connectionStringName"]?.Value;
							if (!string.IsNullOrWhiteSpace(connectionStringName) && connectionStrings.ContainsKey(connectionStringName))
							{
								var attribute = xml.CreateAttribute("connectionString");
								attribute.Value = connectionStrings[connectionStringName];
								dataSourceNode.Attributes.Append(attribute);
							}
						}
						RepositoryStarter.ConstructDataSources(dataSourceNodes, (msg, ex) => Global.OnError(msg, ex));
					}

					if (xml.DocumentElement.SelectNodes("/configuration/dbProviderFactories/add") is XmlNodeList dbProviderFactoryNodes)
					{
						Global.OnProcess("Construct database provider factories");
						RepositoryStarter.ConstructDbProviderFactories(dbProviderFactoryNodes, (msg, ex) => Global.OnError(msg, ex));
					}
				});
		}

		List<string> CleanRecycleBin()
		{
			// prepare data sources
			var versionDataSources = new List<string>();
			var trashDataSources = new List<string>();

			$"{this._serviceHoster}.config|{this._serviceHoster.Replace(".exe", ".x86.exe")}.config".ToList("|")
				.Where(filename => File.Exists(filename))
				.ForEach(filename =>
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
			var stopwatch = new Stopwatch();
			stopwatch.Start();

			// run tasks
			var index = 0;
			while (index < tasks.Count)
			{
				// run a task
				var running = true;
				var task = tasks[index];
				var results = "";
				this._runningTasks.Add(new Tuple<int, string>(UtilityService.RunProcess(
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
						Global.OnProcess(
							"The task is completed" + "\r\n" +
							"- Execution times: " + ((sender as Process).ExitTime - (sender as Process).StartTime).TotalMilliseconds.CastAs<long>().GetElapsedTimes() + "\r\n" +
							"- Command: [" + command.Trim() + "]\r\n" +
							"- Results: " + results
						);
						this._runningTasks.Remove(this._runningTasks.First(info => info.Item1 == (sender as Process).Id));
						running = false;
					},
					(sender, args) =>
					{
						results += string.IsNullOrWhiteSpace(args.Data) ? "" : "\r\n" + args.Data;
					}
				).Id, task.Key));

				// wait for completed
				while (running)
					try
					{
						await Task.Delay(1234, this._cancellationTokenSource.Token).ConfigureAwait(false);
					}
					catch (OperationCanceledException)
					{
						this.KillProcess(this._runningTasks.First(t => t.Item2 == task.Key).Item1);
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
			Global.OnProcess(
				"The task scheduler was completed with all tasks" + "\r\n" +
				"- Number of tasks: " + tasks.Count.ToString() + "\r\n" +
				"- Execution times: " + stopwatch.GetElapsedTimes()
			);
			this._isTaskSchedulerRunning = false;
		}
		#endregion

		#region Process inter-communicate messages
		Task ProcessInterCommunicateMessageAsync(CommunicateMessage message) => Task.CompletedTask;
		#endregion

		#region Dispose
		public void Dispose()
		{
			this.Stop();
			this._cancellationTokenSource.Dispose();
			GC.SuppressFinalize(this);
		}

		~ControlComponent()
		{
			this.Dispose();
		}
		#endregion

	}

}