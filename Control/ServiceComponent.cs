﻿#region Related components
using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Diagnostics;
using System.Configuration;
using System.Threading.Tasks;
using System.Collections.Generic;

using Newtonsoft.Json.Linq;

using WampSharp.V2;
using WampSharp.V2.Core.Contracts;
using WampSharp.V2.Realm;
using WampSharp.Core.Listener;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal class ServiceComponent : IDisposable
	{

		#region Attributes
		internal IWampChannel _incommingChannel = null, _outgoingChannel = null;
		internal long _incommingChannelSessionID = 0, _outgoingChannelSessionID = 0;
		internal bool _channelsAreClosedBySystem = false;

		internal IDisposable _communicator = null;
		internal ManagementService _managementService = null;

		string _serviceHoster = UtilityService.GetAppSetting("ServiceHoster", "VIEApps.Services.APIGateway.Host.exe");
		Dictionary<string, string> _availableServices = new Dictionary<string, string>();
		Dictionary<string, int> _runningServices = new Dictionary<string, int>();

		List<System.Timers.Timer> _timers = new List<System.Timers.Timer>();
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
		internal void Start(string[] args = null, Action nextAction = null, Func<Task> nextActionAsync = null)
		{
			Task.Run(async () =>
			{
				await this.StartAsync(args);
			})
			.ContinueWith(async (task) =>
			{
				try
				{
					nextAction?.Invoke();
				}
				catch (Exception ex)
				{
					Global.WriteLog("Error occurred while running the next action (sync)", ex);
				}
				if (nextActionAsync != null)
					try
					{
						await nextActionAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						Global.WriteLog("Error occurred while running the next action (async)", ex);
					}
			})
			.ConfigureAwait(false);
		}

		internal async Task StartAsync(string[] args = null)
		{
			// open channels
			Global.WriteLog("Start the API Gateway...");

			await this.OpenIncomingChannelAsync(
				(sender, arguments) =>
				{
					Global.WriteLog("The incoming connection is established - Session ID: " + arguments.SessionId);
					this._incommingChannelSessionID = arguments.SessionId;
					this._communicator = this._incommingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.apigateway")
						.Subscribe(
							message => this.ProcessInterCommunicateMessage(message),
							exception => Global.WriteLog("Error occurred while fetching inter-communicate message", exception)
						);
				},
				(sender, arguments) =>
				{
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLog("The incoming connection is broken because the router is not found or the router is refused - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
					else
					{
						if (this._channelsAreClosedBySystem)
							Global.WriteLog("The incoming connection is closed - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
						else
							this.ReOpenIncomingChannel(
								123,
								() =>
								{
									Global.WriteLog("Re-connect the incoming connection successful");
								},
								(ex) =>
								{
									Global.WriteLog("Error occurred while re-connecting the incoming connection", ex);
								}
							);
					}
				},
				(sender, arguments) =>
				{
					Global.WriteLog("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);

			await this.OpenOutgoingChannelAsync(
				(sender, arguments) =>
				{
					Global.WriteLog("The outgoing connection is established - Session ID: " + arguments.SessionId);
					this._outgoingChannelSessionID = arguments.SessionId;
				},
				(sender, arguments) =>
				{
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLog("The outgoing connection is broken because the router is not found or the router is refused - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
					else
					{
						if (this._channelsAreClosedBySystem)
							Global.WriteLog("The outgoing connection is closed - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
						else
							this.ReOpenOutgoingChannel(
								123,
								() =>
								{
									Global.WriteLog("Re-connect the outgoing connection successful");
								},
								(ex) =>
								{
									Global.WriteLog("Error occurred while re-connecting the outgoing connection", ex);
								}
							);
					}
				},
				(sender, arguments) =>
				{
					Global.WriteLog("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);

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
				await this.RegisterHelperServicesAsync();

			// register timers
			if (this._registerTimers)
				this.RegisterTimers();

			// register business services
			if (this._registerBusinessServices)
				this.RegisterBusinessServices();
		}

		internal void Stop()
		{
			MailSender.SaveMessages();
			WebHookSender.SaveMessages();

			this._timers.ForEach(timer => timer.Stop());
			this._runningServices.Select(s => s.Value)
				.Concat(this._runningTasks.Select(s => s.Item1))
				.ToList()
				.ForEach(pid => this.KillProcess(pid));

			this._communicator?.Dispose();
			this._managementService?.FlushAll();
			Global.CancellationTokenSource.Cancel();
			Global.CancellationTokenSource.Dispose();

			this._channelsAreClosedBySystem = true;
			this.CloseIncomingChannel();
			this.CloseOutgoingChannel();
		}
		#endregion

		#region Open/Close channels
		Tuple<string, string, bool> GetLocationInfo()
		{
			var address = UtilityService.GetAppSetting("RouterAddress", "ws://127.0.0.1:26429/");
			var realm = UtilityService.GetAppSetting("RouterRealm", "VIEAppsRealm");
			var mode = UtilityService.GetAppSetting("RouterChannelsMode", "MsgPack");
			return new Tuple<string, string, bool>(address, realm, mode.IsEquals("json"));
		}

		public async Task OpenIncomingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (this._incommingChannel != null)
				return;

			var info = this.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			this._incommingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			if (onConnectionEstablished != null)
				this._incommingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				this._incommingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				this._incommingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await this._incommingChannel.Open();
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
				(new WampChannelReconnector(this._incommingChannel, async () =>
				{
					await Task.Delay(delay > 0 ? delay : 0);
					try
					{
						await this._incommingChannel.Open();
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				})).Start();
		}

		public async Task OpenOutgoingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (this._outgoingChannel != null)
				return;

			var info = this.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			this._outgoingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			if (onConnectionEstablished != null)
				this._outgoingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				this._outgoingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				this._outgoingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await this._outgoingChannel.Open();
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
				(new WampChannelReconnector(this._outgoingChannel, async () =>
				{
					await Task.Delay(delay > 0 ? delay : 0);
					try
					{
						await this._outgoingChannel.Open();
						onSuccess?.Invoke();
					}
					catch (Exception ex)
					{
						onError?.Invoke(ex);
					}
				})).Start();
		}
		#endregion

		#region Register business services
		void  RegisterBusinessServices()
		{
			// prepare
			if (ConfigurationManager.GetSection("net.vieapps.services") is AppConfigurationSectionHandler config)
				if (config.Section.SelectNodes("./add") is XmlNodeList nodes)
					foreach (XmlNode node in nodes)
					{
						var info = config.GetJson(node);

						var name = info["name"] != null
							? (info["name"] as JValue).Value as string
							: null;
						var type = info["type"] != null
							? (info["type"] as JValue).Value as string
							: null;

						if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(type))
							this._availableServices[name.ToLower().Trim()] = type.Trim().Replace(" ", "");
					}

			// register
			if (File.Exists(this._serviceHoster))
				this._availableServices.ForEach(s => this.StartService(s.Key));
			else if (!Global.AsService)
				Global.Form.UpdateLogs($"The service hoster [{this._serviceHoster}] is not found");

			// update info
			this.UpdateServicesInfo();
		}

		void UpdateServicesInfo()
		{
			if (!Global.AsService)
				Global.Form.UpdateServicesInfo(this._availableServices.Count, this._runningServices.Count);
		}
		#endregion

		#region Start/Stop business service
		internal void StartService(string name, string arguments = null)
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

			Global.WriteLog($"The service [{name.ToLower()}] is starting...");
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
								"--------------------------------------------------------------------------------" + "\r\n"
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
								"--------------------------------------------------------------------------------" + "\r\n"
							);
						}
						catch { }
				}
			);

			this._runningServices[name.ToLower()] = process.Id;
			Global.WriteLog($"The service [{name.ToLower()}] is started - PID: {process.Id}");

			if (!Global.AsService)
				this.UpdateServicesInfo();
		}

		internal void StopService(string name)
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

					UtilityService.RunProcess(
						serviceHoster,
						serviceArguments,
						(sender, args) =>
						{
							this.KillProcess(processID);
						}
					);

					// update information
					this._runningServices.Remove(name.ToLower());
					if (!Global.AsService)
						this.UpdateServicesInfo();
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
			this._managementService = new ManagementService();
			await this._incommingChannel.RealmProxy.Services.RegisterCallee(this._managementService, new CalleeRegistrationInterceptor(new RegisterOptions() { Invoke = WampInvokePolicy.Roundrobin }));
			Global.WriteLog("The management service is registered");

			await this._incommingChannel.RealmProxy.Services.RegisterCallee(new RTUService(), new CalleeRegistrationInterceptor(new RegisterOptions() { Invoke = WampInvokePolicy.Roundrobin }));
			Global.WriteLog("The real-time update (RTU) service is registered");

			await this._incommingChannel.RealmProxy.Services.RegisterCallee(new MessagingService(), new CalleeRegistrationInterceptor(new RegisterOptions() { Invoke = WampInvokePolicy.Roundrobin }));
			Global.WriteLog("The messaging service is registered");
		}
		#endregion

		#region Register timers for working with background workers & schedulers
		void RegisterTimers()
		{
			this.RegisterMessagingTimers();
			this.RegisterSchedulingTimers();
			Global.WriteLog("The background workers & schedulers are registered");
		}

		void StartTimer(int interval, Action<object, System.Timers.ElapsedEventArgs> action, bool autoReset = true)
		{
			var timer = new System.Timers.Timer()
			{
				Interval = interval * 1000,
				AutoReset = autoReset
			};
			timer.Elapsed += new System.Timers.ElapsedEventHandler(action);
			timer.Start();
			this._timers.Add(timer);
		}

		void RegisterMessagingTimers()
		{
			// send email messages (15 seconds)
			this.StartTimer(15, (sender, args) =>
			{
				if (this._mailSender == null)
					Task.Run(async () =>
					{
						this._mailSender = new MailSender();
						try
						{
							await this._mailSender.ProcessAsync();
						}
						catch { }
						finally
						{
							this._mailSender = null;
						}
					}).ConfigureAwait(false);
			});

			// send web hook messages (25 seconds)
			this.StartTimer(25, (sender, args) =>
			{
				if (this._webhookSender == null)
					Task.Run(async () =>
					{
						this._webhookSender = new WebHookSender();
						try
						{
							await this._webhookSender.ProcessAsync();
						}
						catch { }
						finally
						{
							this._webhookSender = null;
						}
					}).ConfigureAwait(false);
			});
		}

		void RegisterSchedulingTimers()
		{
			// prepare task scheduler
			var runTaskSchedulerOnFirstLoad = false;
			if (ConfigurationManager.GetSection("net.vieapps.task.scheduler") is AppConfigurationSectionHandler config)
			{
				runTaskSchedulerOnFirstLoad = "true".IsEquals(config.Section.Attributes["runOnFirstLoad"]?.Value);
				if (config.Section.SelectNodes("task") is XmlNodeList taskNodes)
					foreach (XmlNode taskNode in taskNodes)
					{
						var settings = config.GetJson(taskNode);
						var execute = settings["execute"] as JValue;
						var arguments = settings["arguments"] as JValue;
						var time = settings["time"] as JValue;

						if (string.IsNullOrWhiteSpace(execute?.Value as string) || !File.Exists(execute.Value as string))
							continue;

						var info = new Tuple<string, string, string>(
							(execute.Value as string).Trim(),
							(arguments?.Value as string ?? "").Trim(),
							time?.Value as string ?? "3"
						);

						var identity = (info.Item1 + "[" + (arguments?.Value as string ?? "") + "]").ToLower().GetMD5();
						if (!this._tasks.ContainsKey(identity))
							this._tasks.Add(identity, info);
					}
			}

#if DEBUG
			// timer to flush logs (10 seconds)
			this.StartTimer(10, (sender, args) =>
#else
			// timer to flush logs (3 minutes)
			this.StartTimer(60 * 3, (sender, args) =>
#endif
			{
				this._managementService?.FlushAll();
			});

			// timer to run house keeper & task scheduler (hourly)
			this.StartTimer(60 * 60, (sender, args) =>
			{
				this.RunHouseKeeper();
				Task.Run(async () =>
				{
					await this.RunTaskSchedulerAsync();
				}).ConfigureAwait(false);
			});

			// run task scheduler on first-load
			if (runTaskSchedulerOnFirstLoad)
				Task.Run(async () =>
				{
					await Task.Delay(1234);
					await this.RunTaskSchedulerAsync();
				}).ConfigureAwait(false);
		}

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

			stopwatch.Stop();
			Global.WriteLog(
				"The house keeper is complete the working..." + "\r\n\r\n=> " + paths.ToString("\r\n=> ") + "\r\n\r\n" +
				"- Total of cleaned files: " + counter.ToString("###,##0") + "\r\n" +
				"- Execution times: " + stopwatch.GetElapsedTimes()
			);
			this._isHouseKeeperRunning = false;
		}

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
						Global.WriteLog(
							"The task is completed" + "\r\n" +
							"- Execution times: " + ((sender as Process).ExitTime - (sender as Process).StartTime).TotalMilliseconds.CastAs<long>().GetElapsedTimes() + "\r\n" +
							"- Command: [" + (task.Value.Item1 + " " + task.Value.Item2).Trim() + "]\r\n" +
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
						await Task.Delay(1234, Global.CancellationTokenSource.Token);
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
				"- Execution times: " + stopwatch.GetElapsedTimes()
			);
			this._isTaskSchedulerRunning = false;
		}
		#endregion

		#region Process inter-communicate messages
		void ProcessInterCommunicateMessage(CommunicateMessage message)
		{

		}
		#endregion

	}
}