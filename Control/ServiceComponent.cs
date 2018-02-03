#region Related components
using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Diagnostics;
using System.Configuration;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Reactive.Linq;

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
	internal class ServiceComponent : IServiceManager, IDisposable
	{

		#region Attributes
		internal IWampChannel _incommingChannel = null, _outgoingChannel = null;
		internal long _incommingChannelSessionID = 0, _outgoingChannelSessionID = 0;
		internal bool _channelsAreClosedBySystem = false;
		internal string _status = "Initializing";

		internal IDisposable _communicator = null;
		internal LoggingService _loggingService = null;

		string _serviceHoster = UtilityService.GetAppSetting("ServiceHoster", "VIEApps.Services.APIGateway.Host.exe");
		internal Dictionary<string, string> _availableServices = null;
		Dictionary<string, int> _runningServices = new Dictionary<string, int>();
		List<SystemEx.IAsyncDisposable> _helperServices = new List<SystemEx.IAsyncDisposable>();

		List<IDisposable> _timers = new List<IDisposable>();
		MailSender _mailSender = null;
		WebHookSender _webhookSender = null;
		bool _isHouseKeeperRunning = false, _isTaskSchedulerRunning = false;
		Dictionary<string, Tuple<string, string, string>> _tasks = new Dictionary<string, Tuple<string, string, string>>();
		List<Tuple<int, string>> _runningTasks = new List<Tuple<int, string>>();

		bool _registerHelperServices = true, _registerBusinessServices = true, _registerTimers = true;
		#endregion

		#region Constructor & Destructor
		public ServiceComponent() { }

		~ServiceComponent()
		{
			this.Dispose();
		}

		public void Dispose()
		{
			this.Stop();
			GC.SuppressFinalize(this);
		}
		#endregion

		#region Start/Stop
		internal void Start(string[] args = null, Func<Task> next = null)
		{
			this._loggingService = new LoggingService();
			Task.Run(async () =>
			{
				await this.StartAsync(args).ConfigureAwait(false);
			})
			.ContinueWith(async (task) =>
			{
				if (next != null)
					try
					{
						await next().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.WriteLog("Error occurred while running the next action", ex, "Controller", 36429);
					}
			})
			.ConfigureAwait(false);
		}

		internal async Task StartAsync(string[] args = null)
		{
			// connecto to WAMP router to open channels
			var info = this.GetRouterInfo();
			Global.WriteLog($"Start the API Gateway Services Controller - Working mode: {(Global.AsService ? "Background Service" : "Desktop App")}", "Controller");
			Global.WriteLog($"Attempts connect to WAMP router [{info.Item1}{info.Item2}]", "Controller");

			await this.OpenIncomingChannelAsync(
				(sender, arguments) =>
				{
					Global.WriteLog($"The incoming connection is established - Session ID: {arguments.SessionId}", "Controller");
					this._incommingChannelSessionID = arguments.SessionId;
					this._communicator = this._incommingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
						.Subscribe(
							async (message) =>
							{
								await this.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false);
							},
							exception => Global.WriteLog("Error occurred while fetching inter-communicate message", exception, "Controller", 36429)
						);
				},
				(sender, arguments) =>
				{
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLog($"The incoming connection is broken because the router is not found or the router is refused - Session ID: {arguments.SessionId}\r\n- Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}", "Controller", 36429);
					else
					{
						if (this._channelsAreClosedBySystem)
							Global.WriteLog($"The incoming connection is closed - Session ID: {arguments.SessionId}\r\n- Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}", "Controller");
						else
							this.ReOpenIncomingChannel(
								123,
								() =>
								{
									Global.WriteLog("Re-connect the incoming connection successful", "Controller");
								},
								(ex) =>
								{
									Global.WriteLog("Error occurred while re-connecting the incoming connection", ex, "Controller", 36429);
								}
							);
					}
				},
				(sender, arguments) =>
				{
					Global.WriteLog($"Got an error of incoming connection [{(arguments.Exception != null ? arguments.Exception.Message : "None")}", arguments.Exception, "Controller", 36429);
				}
			).ConfigureAwait(false);

			await this.OpenOutgoingChannelAsync(
				(sender, arguments) =>
				{
					Global.WriteLog($"The outgoing connection is established - Session ID: {arguments.SessionId}", "Controller");
					this._outgoingChannelSessionID = arguments.SessionId;
					if (!Global.AsService)
						Global.ServiceManager = this._outgoingChannel.RealmProxy.Services.GetCalleeProxy<IServiceManager>(ProxyInterceptor.Create());
				},
				(sender, arguments) =>
				{
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLog($"The outgoing connection is broken because the router is not found or the router is refused - Session ID: {arguments.SessionId}\r\n- Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}", "Controller", 36429);
					else
					{
						if (this._channelsAreClosedBySystem)
							Global.WriteLog($"The outgoing connection is closed - Session ID: {arguments.SessionId}\r\n- Reason: {(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)} - {arguments.CloseType}", "Controller");
						else
							this.ReOpenOutgoingChannel(
								123,
								() =>
								{
									Global.WriteLog("Re-connect the outgoing connection successful", "Controller");
								},
								(ex) =>
								{
									Global.WriteLog("Error occurred while re-connecting the outgoing connection", ex, "Controller", 36429);
								}
							);
					}
				},
				(sender, arguments) =>
				{
					Global.WriteLog($"Got an error of outgoing connection [{(arguments.Exception != null ? arguments.Exception.Message : "None")}", arguments.Exception, "Controller", 36429);
				}
			).ConfigureAwait(false);

			// prepare arguments
#if !DEBUG
			if (!Global.AsService)
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

			// prepare folder of logs/emails/webhooks
			(Global.LogsPath + "," + Global.StatusPath + "," + Global.EmailsPath + "," + Global.WebHooksPath)
				.ToArray()
				.Where(path => !Directory.Exists(path))
				.ForEach(path => Directory.CreateDirectory(path));

			// register helper services
			if (this._registerHelperServices)
				await this.RegisterHelperServicesAsync().ConfigureAwait(false);

			// call service to update status
			else
				this._status = "Ready";

			// register timers
			if (this._registerTimers)
			{
				this.RegisterMessagingTimers();
				this.RegisterSchedulingTimers();
				Global.WriteLog("The background workers & schedulers are registered", "Controller");
			}

			// register business services
			if (this._registerBusinessServices)
				this.RegisterBusinessServices();
		}

		internal void Stop()
		{
			Global.CancellationTokenSource.Cancel();
			Global.CancellationTokenSource.Dispose();

			MailSender.SaveMessages();
			WebHookSender.SaveMessages();

			this._timers.ForEach(timer => timer.Dispose());
			this._runningTasks.Select(s => s.Item1).ToList().ForEach(pid => this.KillProcess(pid));
			this._runningServices.Select(kvp => kvp.Key).ToList().ForEach(name => this.StopBusinessService(name, false));

			this._communicator?.Dispose();
			this._loggingService?.FlushAllLogs();

			this._helperServices.ForEach(async (s) => await s.DisposeAsync().ConfigureAwait(false));

			this._channelsAreClosedBySystem = true;
			this.CloseIncomingChannel();
			this.CloseOutgoingChannel();
		}
		#endregion

		#region Open/Close channels
		Tuple<string, string, bool> GetRouterInfo()
		{
			var address = UtilityService.GetAppSetting("Router:Address", "ws://127.0.0.1:16429/");
			var realm = UtilityService.GetAppSetting("Router:Realm", "VIEAppsRealm");
			var mode = UtilityService.GetAppSetting("Router:ChannelsMode", "MsgPack");
			return new Tuple<string, string, bool>(address, realm, mode.IsEquals("json"));
		}

		public async Task OpenIncomingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (this._incommingChannel != null)
				return;

			var info = this.GetRouterInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			this._incommingChannel = useJsonChannel
				? new DefaultWampChannelFactory().CreateJsonChannel(address, realm)
				: new DefaultWampChannelFactory().CreateMsgpackChannel(address, realm);

			if (onConnectionEstablished != null)
				this._incommingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				this._incommingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				this._incommingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await this._incommingChannel.Open().ConfigureAwait(false);
		}

		public void CloseIncomingChannel()
		{
			if (this._incommingChannel != null)
			{
				this._incommingChannel.Close("The incoming channel is closed when stop the API Gateway Services Controller", new GoodbyeDetails());
				this._incommingChannel = null;
			}
		}

		void ReOpenIncomingChannel(int delay = 0, Action onSuccess = null, Action<Exception> onError = null)
		{
			if (this._incommingChannel != null)
				new WampChannelReconnector(this._incommingChannel, async () =>
				{
					await Task.Delay(delay > 0 ? delay : 0).ConfigureAwait(false);
					try
					{
						await this._incommingChannel.Open().ConfigureAwait(false);
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				}).Start();
		}

		public async Task OpenOutgoingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (this._outgoingChannel != null)
				return;

			var info = this.GetRouterInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			this._outgoingChannel = useJsonChannel
				? new DefaultWampChannelFactory().CreateJsonChannel(address, realm)
				: new DefaultWampChannelFactory().CreateMsgpackChannel(address, realm);

			if (onConnectionEstablished != null)
				this._outgoingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				this._outgoingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				this._outgoingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await this._outgoingChannel.Open().ConfigureAwait(false);
		}

		public void CloseOutgoingChannel()
		{
			if (this._outgoingChannel != null)
			{
				this._outgoingChannel.Close("The outgoing channel is closed when stop the API Gateway Services Controller", new GoodbyeDetails());
				this._outgoingChannel = null;
			}
		}

		void ReOpenOutgoingChannel(int delay = 0, Action onSuccess = null, Action<Exception> onError = null)
		{
			if (this._outgoingChannel != null)
				new WampChannelReconnector(this._outgoingChannel, async () =>
				{
					await Task.Delay(delay > 0 ? delay : 0);
					try
					{
						await this._outgoingChannel.Open().ConfigureAwait(false);
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				}).Start();
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
				Global.WriteLog($"The service hoster [{this._serviceHoster}] is not found", null, "Controller", 36429);

			// update info
			this.UpdateServicesInfo();
		}

		void UpdateServicesInfo()
		{
			if (!Global.AsService)
				Global.MainForm.UpdateServicesInfo(this._availableServices.Count, this._runningServices.Count);
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
			var serviceArguments = (arguments ?? "") + $" /agc:{(Global.AsService ? "r" : "g")} /svc:{serviceType} /svn:{name.ToLower()}";

			Global.WriteLog($"The service [{name.ToLower()}] is starting...", "Controller");
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
							Global.WriteLog(
								$"----- [{serviceName.ToLower().Replace("/svn:", "")}] -----" + "\r\n" +
								"The sevice is stopped..." + "\r\n" +
								"--------------------------------------------------------------------------------" + "\r\n",
								"Controller"
							);
						}

						if (!Global.AsService)
							this.UpdateServicesInfo();
					}
					catch { }
				},
				(sender, args) =>
				{
					var serviceName = (sender as Process).StartInfo.Arguments.Split(' ').FirstOrDefault(a => a.IsStartsWith("/svn:"));
					if (!string.IsNullOrWhiteSpace(serviceName) && !string.IsNullOrWhiteSpace(args.Data))
						try
						{
							Global.WriteLog(
								$"----- [{serviceName.ToLower().Replace("/svn:", "")}] -----" + "\r\n" +
								args.Data + "\r\n" +
								"--------------------------------------------------------------------------------" + "\r\n",
								"Controller"
							);
						}
						catch { }
				}
			);

			this._runningServices[name.ToLower()] = process.Id;
			Global.WriteLog($"The service [{name.ToLower()}] is started - PID: {process.Id}", "Controller");

			if (!Global.AsService)
				this.UpdateServicesInfo();
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
						serviceHoster = serviceHoster.Replace(StringComparison.OrdinalIgnoreCase, ".exe", ".x86.exe");
						serviceType = serviceType.Left(serviceType.Length - 4);
					}
					var serviceArguments = $"/agc:s /svc:{serviceType} /svn:{name.ToLower()}";
					UtilityService.RunProcess(serviceHoster, serviceArguments, (sender, args) => this.KillProcess(processID));

					// update status
					if (updateStatus)
					{
						this._runningServices.Remove(name.ToLower());
						if (!Global.AsService)
							this.UpdateServicesInfo();
					}
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
				this._helperServices.Add(await this._incommingChannel.RealmProxy.Services.RegisterCallee(this, new RegistrationInterceptor(null, new RegisterOptions() { Invoke = WampInvokePolicy.Single })).ConfigureAwait(false));
				Global.WriteLog("The centralized managing service is registered", "Controller");
			}
			catch (Exception ex)
			{
				Global.WriteLog("Error occurred while registering the centralized managing service", ex, "Controller", 36429);
			}

			this._helperServices.Add(await this._incommingChannel.RealmProxy.Services.RegisterCallee(this._loggingService, RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.WriteLog("The centralized logging service is registered", "Controller");

			this._helperServices.Add(await this._incommingChannel.RealmProxy.Services.RegisterCallee(new MessagingService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.WriteLog("The centralized messaging service is registered", "Controller");

			this._helperServices.Add(await this._incommingChannel.RealmProxy.Services.RegisterCallee(new RTUService(), RegistrationInterceptor.Create()).ConfigureAwait(false));
			Global.WriteLog("The real-time update (RTU) service is registered", "Controller");

			this._status = "Ready";
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
					this._mailSender = new MailSender();
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
					this._webhookSender = new WebHookSender();
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

			var paths = new HashSet<string>()
			{
				Global.LogsPath,
				Global.StatusPath
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
			remainTime = DateTime.Now.AddHours(-24);
			UtilityService.GetFiles(Global.LogsPath, "*.*")
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
			Global.WriteLog(
				"The house keeper is complete the working..." + "\r\n\r\nPaths\r\n=> " + paths.ToString("\r\n=> ") + "\r\n\r\n" +
				"Total of cleaned files: " + counter.ToString("###,##0") + "\r\n\r\n" +
				"Recycle-Bin\r\n\t" + logs.ToString("\r\n\t") + "\r\n\r\n" +
				"Execution times: " + stopwatch.GetElapsedTimes(),
				"HouseKeeper"
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
						Global.WriteLog("Construct data sources", "Controller");
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
						RepositoryStarter.ConstructDataSources(dataSourceNodes, (msg, ex) =>
						{
							Global.WriteLog(msg, ex, "Controller");
						});
					}

					if (xml.DocumentElement.SelectNodes("/configuration/dbProviderFactories/add") is XmlNodeList dbProviderFactoryNodes)
					{
						Global.WriteLog("Construct database provider factories", "Controller");
						RepositoryStarter.ConstructDbProviderFactories(dbProviderFactoryNodes, (msg, ex) =>
						{
							Global.WriteLog(msg, ex, "Controller");
						});
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
						Global.WriteLog(
							"The task is completed" + "\r\n" +
							"- Execution times: " + ((sender as Process).ExitTime - (sender as Process).StartTime).TotalMilliseconds.CastAs<long>().GetElapsedTimes() + "\r\n" +
							"- Command: [" + command.Trim() + "]\r\n" +
							"- Results: " + results,
							"TaskScheduler"
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
						await Task.Delay(1234, Global.CancellationTokenSource.Token).ConfigureAwait(false);
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
			Global.WriteLog(
				"The task scheduler was completed with all tasks" + "\r\n" +
				"- Number of tasks: " + tasks.Count.ToString() + "\r\n" +
				"- Execution times: " + stopwatch.GetElapsedTimes(),
				"TaskScheduler"
			);
			this._isTaskSchedulerRunning = false;
		}
		#endregion

		#region Process inter-communicate messages
		Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			return Task.CompletedTask;
		}
		#endregion

	}

	#region Service Manager
	public interface IServiceManager
	{
		[WampProcedure("net.vieapps.apigateway.controller.get")]
		Dictionary<string, string> GetAvailableBusinessServices();

		[WampProcedure("net.vieapps.apigateway.controller.state")]
		bool IsBusinessServiceRunning(string name);

		[WampProcedure("net.vieapps.apigateway.controller.start")]
		void StartBusinessService(string name, string arguments = null);

		[WampProcedure("net.vieapps.apigateway.controller.stop")]
		void StopBusinessService(string name, bool updateStatus = true);
	}
	#endregion

}