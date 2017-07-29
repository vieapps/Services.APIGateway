#region Related components
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Configuration;

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

		#region Start
		bool _channelAreClosedBySystem = false;
		ManagementService _managementService = null;
		RTUService _rtuService = null;
		Dictionary<string, int> _services = new Dictionary<string, int>();

		internal async Task StartAsync(string[] args = null)
		{
			// open channels
			Global.WriteLog("Starting the API Gateway...");
			await this.OpenIncomingChannelAsync(
				(sender, arguments) => {
					Global.WriteLog("The incoming connection is established" + "\r\n" + " - Session ID: " + arguments.SessionId + "\r\n");
				},
				(sender, arguments) => {
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLog("The incoming connection is broken because the router is not found or the router is refused" + "\r\n" + " - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString() + "\r\n");
					else
					{
						if (this._channelAreClosedBySystem)
							Global.WriteLog("The incoming connection is closed" + "\r\n" + " - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString() + "\r\n");
						else
							this.ReOpenIncomingChannel(
								123,
								() => {
									Global.WriteLog("Re-connect the incoming connection successful" + "\r\n");
								}, (ex) => {
									Global.WriteLog("Error occurred while re-connecting the incoming connection", ex);
								}
							);
					}
				},
				(sender, arguments) => {
					Global.WriteLog("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);

			await this.OpenOutgoingChannelAsync(
				(sender, arguments) => {
					Global.WriteLog("The outgoing connection is established" + "\r\n" + " - Session ID: " + arguments.SessionId + "\r\n");
				},
				(sender, arguments) => {
					if (arguments.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLog("The outgoing connection is broken because the router is not found or the router is refused" + "\r\n" + " - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString() + "\r\n");
					else
					{
						if (this._channelAreClosedBySystem)
							Global.WriteLog("The outgoing connection is closed" + "\r\n" + " - Session ID: " + arguments.SessionId + "\r\n" + "- Reason: " + (string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason) + " - " + arguments.CloseType.ToString() + "\r\n");
						else
							this.ReOpenOutgoingChannel(
								123,
								() => {
									Global.WriteLog("Re-connect the outgoing connection successful" + "\r\n");
								}, (ex) => {
									Global.WriteLog("Error occurred while re-connecting the outgoing connection", ex);
								}
							);
					}
				},
				(sender, arguments) => {
					Global.WriteLog("Got an error of incoming connection: " + (arguments.Exception != null ? arguments.Exception.Message : "None"), arguments.Exception);
				}
			);

			// register helper services
			var registerHelperServices = true;
			if (args != null && args.Length > 0)
				for (var index = 0; index < args.Length; index++)
					if (args[index].IsStartsWith("/helper-services:"))
					{
						if (args[index].IsEndsWith(":false"))
							registerHelperServices = false;
						break;
					}

			if (registerHelperServices)
			{
				this._managementService = new ManagementService();
				await this._incommingChannel.RealmProxy.Services.RegisterCallee(this._managementService, new CalleeRegistrationInterceptor(new RegisterOptions() { Invoke = WampInvokePolicy.Roundrobin }));
				Global.WriteLog("The management service is registered");

				this._rtuService = new RTUService();
				await this._incommingChannel.RealmProxy.Services.RegisterCallee(this._rtuService, new CalleeRegistrationInterceptor(new RegisterOptions() { Invoke = WampInvokePolicy.Roundrobin }));
				Global.WriteLog("The real-time update (RTU) service is registered");
			}

			// register business services
			this.RegisterServices(args);
		}

		void RegisterServices(string[] args = null)
		{
			var current = Process.GetCurrentProcess().ProcessName + ".exe";
			UtilityService.GetFiles(Directory.GetCurrentDirectory(), "*.exe")
				.Where(info => !info.Name.IsEquals(current))
				.ForEach(info => 
				{
					var name = info.Name;
					if (!this._services.ContainsKey(name))
					{
						var process = UtilityService.RunProcess(name, null,
							(sender, arguments) => {
								this._services.Remove((sender as Process).StartInfo.FileName);
								Global.WriteLog("The service of [" + (sender as Process).StartInfo.FileName + " - PID: " + (sender as Process).Id.ToString() + "] is stopped...");
							},
							(sender, arguments) => {
								Global.WriteLog(
									"[" + (sender as Process).StartInfo.FileName + " - PID: " + (sender as Process).Id.ToString() + "] -------------" + "\r\n" +
									arguments.Data + "\r\n" +
									"--------------------------------------------------------------" + "\r\n"
								);
							}
						);
						this._services.Add(name, process.Id);
						Global.WriteLog("The service of [" + name + " - PID: " + process.Id.ToString() + "] is running...");
					}
				});
		}
		#endregion

		#region Stop
		internal void Stop()
		{
			if (this._managementService != null)
				this._managementService.FlushAll();

			this._services
				.Select(info => info.Value)
				.ToList()
				.ForEach(id =>
				{
					UtilityService.KillProcess(id);
				});
			this._services.Clear();

			this._channelAreClosedBySystem = true;
			this.CloseIncomingChannel();
			this.CloseOutgoingChannel();
		}

		void OnCloseIncomingChannel()
		{
		}

		void OnCloseOutgoingChannel()
		{
		}
		#endregion

		#region Open/Close channels
		protected virtual Tuple<string, string, bool> GetLocationInfo()
		{
			var address = ConfigurationManager.AppSettings["Address"];
			if (string.IsNullOrEmpty(address))
				address = "ws://127.0.0.1:26429/";

			var realm = ConfigurationManager.AppSettings["Realm"];
			if (string.IsNullOrEmpty(realm))
				realm = "VIEAppsRealm";

			var mode = ConfigurationManager.AppSettings["Mode"];
			if (string.IsNullOrEmpty(mode))
				mode = "MsgPack";

			return new Tuple<string, string, bool>(address, realm, mode.IsEquals("json"));
		}

		internal IWampChannel _incommingChannel = null;

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
				this.OnCloseIncomingChannel();
				this._incommingChannel.Close();
				this._incommingChannel = null;
			}
		}

		protected void ReOpenIncomingChannel(int delay = 0, Action onSuccess = null, Action<Exception> onError = null)
		{
			if (this._incommingChannel != null)
				(new WampChannelReconnector(this._incommingChannel, async () =>
				{
					if (delay > 0)
						await Task.Delay(delay);

					try
					{
						await this._incommingChannel.Open();
						if (onSuccess != null)
							onSuccess();
					}
					catch (Exception ex)
					{
						if (onError != null)
							onError(ex);
					}
				})).Start();
		}

		internal IWampChannel _outgoingChannel = null;

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
				this.OnCloseOutgoingChannel();
				this._outgoingChannel.Close();
				this._outgoingChannel = null;
			}
		}

		protected void ReOpenOutgoingChannel(int delay = 0, Action onSuccess = null, Action<Exception> onError = null)
		{
			if (this._outgoingChannel != null)
				(new WampChannelReconnector(this._outgoingChannel, async () =>
				{
					if (delay > 0)
						await Task.Delay(delay);

					try
					{
						await this._outgoingChannel.Open();
						if (onSuccess != null)
							onSuccess();
					}
					catch (Exception ex)
					{
						if (onError != null)
							onError(ex);
					}
				})).Start();
		}
		#endregion

	}
}
