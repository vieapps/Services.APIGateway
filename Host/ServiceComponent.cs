#region Related components
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

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
		long _incommingChannelSessionID = 0, _outgoingChannelSessionID = 0;
		bool _channelsAreClosedBySystem = false;

		internal ManagementService _managementService = null;
		internal List<string> _availableServices = null;
		internal Dictionary<string, int> _runningServices = new Dictionary<string, int>();
		internal List<System.Timers.Timer> _timers = new List<System.Timers.Timer>();

		MailSender _mailSender = null;
		WebHookSender _webhookSender = null;

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
			Global.WriteLog("Start the API Gateway Hosting Service...");

			await this.OpenIncomingChannelAsync(
				(sender, arguments) =>
				{
					Global.WriteLog("The incoming connection is established - Session ID: " + arguments.SessionId + "\r\n");
					this._incommingChannelSessionID = arguments.SessionId;
				},
				(sender, arguments) =>
				{
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLog("The incoming connection is broken because the router is not found or the router is refused - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString() + "\r\n");
					else
					{
						if (this._channelsAreClosedBySystem)
							Global.WriteLog("The incoming connection is closed - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString() + "\r\n");
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
					Global.WriteLog("The outgoing connection is established - Session ID: " + arguments.SessionId + "\r\n");
					this._outgoingChannelSessionID = arguments.SessionId;
				},
				(sender, arguments) =>
				{
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLog("The outgoing connection is broken because the router is not found or the router is refused - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString());
					else
					{
						if (this._channelsAreClosedBySystem)
							Global.WriteLog("The outgoing connection is closed - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString() + "\r\n");
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
			if (!Global.AsService && args != null)
				for (var index = 0; index < args.Length; index++)
				{
					if (args[index].IsStartsWith("/helper-services:"))
						this._registerHelperServices = args[index].IsEquals("/helper-services:true");
					else if (args[index].IsStartsWith("/business-services:"))
						this._registerBusinessServices = args[index].IsEquals("/business-services:true");
					else if (args[index].IsStartsWith("/timers:"))
						this._registerTimers = args[index].IsEquals("/timers:true");
				}
#endif

			// register helper services
			if (this._registerHelperServices)
				await this.RegisterHelperServicesAsync();

			// register business services
			if (this._registerBusinessServices)
				this.RegisterBusinessServices();

			// register timers
			if (this._registerTimers)
				this.RegisterTimers();

			// prepare folder of logs/emails/webhooks
			(Global.LogsPath + "," + Global.StatusPath + "," + Global.EmailsPath + "," + Global.WebHooksPath).ToArray()
				.ForEach(path =>
				{
					if (!Directory.Exists(path))
						Directory.CreateDirectory(path);
				});
		}

		internal void Stop()
		{
			Global.CancellationTokenSource.Cancel();
			this._managementService?.FlushAll();

			MailSender.SaveMessages();
			WebHookSender.SaveMessages();

			this._timers.ForEach(timer => timer.Stop());
			this._runningServices.Select(i => i.Value).ToList().ForEach(i => this.KillService(i));

			this._channelsAreClosedBySystem = true;
			this.CloseIncomingChannel();
			this.CloseOutgoingChannel();
		}
		#endregion

		#region Open/Close channels
		protected virtual Tuple<string, string, bool> GetLocationInfo()
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
				this._incommingChannel.Close("The incoming channel is closed when stop the API Gateway Hosting Service", new GoodbyeDetails());
				this._incommingChannel = null;
			}
		}

		protected void ReOpenIncomingChannel(int delay = 0, Action onSuccess = null, Action<Exception> onError = null)
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
				this._outgoingChannel.Close("The outgoing channel is closed when stop the API Gateway Hosting Service", new GoodbyeDetails());
				this._outgoingChannel = null;
			}
		}

		protected void ReOpenOutgoingChannel(int delay = 0, Action onSuccess = null, Action<Exception> onError = null)
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
		internal void  RegisterBusinessServices()
		{
			// register
			this._availableServices = this._availableServices ?? this.GetAvailableServices();
			this._availableServices.ForEach(name => this.StartService(name));

			// update info
			this.UpdateServicesInfo();
		}

		internal void UpdateServicesInfo()
		{
			if (!Global.AsService)
				Global.Form.UpdateServicesInfo(this._availableServices != null ? this._availableServices.Count : 0, this._runningServices != null ? this._runningServices.Count : 0);
		}

		internal List<string> GetAvailableServices()
		{
			var current = Process.GetCurrentProcess().ProcessName + ".exe";
			return UtilityService.GetFiles(Directory.GetCurrentDirectory(), "*.exe")
				.Where(info => !info.Name.IsEquals(current))
				.Select(info => info.Name)
				.ToList();
		}
		#endregion

		#region Start/Stop business service
		internal void StartService(string name, string arguments = null)
		{
			if (string.IsNullOrWhiteSpace(name) || this._runningServices.ContainsKey(name.ToLower()))
				return;

			var process = UtilityService.RunProcess(
				name,
				(!string.IsNullOrEmpty(arguments) ? arguments + " " : "") + "/agc:" + (Global.AsService ? "r" : "g"),
				(sender, args) =>
				{
					try
					{
						this._runningServices.Remove((sender as Process).StartInfo.FileName.ToLower());
						if (!Global.AsService)
							this.UpdateServicesInfo();
						Global.WriteLog(
							"----- [" + (sender as Process).StartInfo.FileName + " - PID: " + (sender as Process).Id.ToString() + "] ------------------" + "\r\n" +
							"The sevice is stopped..." + "\r\n" +
							"--------------------------------------------------------------------------------" + "\r\n"
						);
					}
					catch { }
				},
				(sender, args) =>
				{
					if (!string.IsNullOrWhiteSpace(args.Data))
						try
						{
							Global.WriteLog(
								"----- [" + (sender as Process).StartInfo.FileName + " - PID: " + (sender as Process).Id.ToString() + "] ------------------" + "\r\n" +
								args.Data + "\r\n" +
								"--------------------------------------------------------------------------------" + "\r\n"
							);
						}
						catch { }
				}
			);

			this._runningServices.Add(name.ToLower(), process.Id);
			Global.WriteLog("The service [" + name + " - PID: " + process.Id.ToString() + "] is running...");
		}

		internal void StopService(string name)
		{
			if (!string.IsNullOrWhiteSpace(name) && this._runningServices.ContainsKey(name.ToLower()))
				try
				{
					// call service one time to exit
					if (Global.AsService)
						UtilityService.RunProcess(name, "/agc:s");

					// kill the process if still running
					this.KillService(this._runningServices[name.ToLower()]);

					// update information
					this._runningServices.Remove(name.ToLower());
					if (!Global.AsService)
						this.UpdateServicesInfo();
				}
				catch { }
		}

		internal void KillService(int serviceProcessID)
		{
			try
			{
				UtilityService.KillProcess(serviceProcessID);
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

		#region Register timers for working with schedulers
		void StartTimer(int interval, Action<object, System.Timers.ElapsedEventArgs> action, bool autoReset = true)
		{
			var timer = new System.Timers.Timer() { Interval = interval * 1000, AutoReset = autoReset };
			timer.Elapsed += new System.Timers.ElapsedEventHandler(action);
			timer.Start();
			this._timers.Add(timer);
		}

		void RegisterTimers()
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

			Global.WriteLog("The schedulers are registered");
		}
		#endregion

	}
}
