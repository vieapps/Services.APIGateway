#region Related components
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class WebHookSender
	{
		public WebHookSender() { }

		#region Information
		static Dictionary<string, WebHookInfo> Messages = null;

		public class WebHookInfo
		{
			public WebHookInfo()
			{
				this.Message = null;
				this.Time = DateTime.Now;
				this.Counters = 0;
			}

			public WebHookMessage Message { get; set; }
			public DateTime Time { get; set; }
			public int Counters { get; set; }
		}
		#endregion

		#region Load & Save messages
		internal static void LoadMessages()
		{
			WebHookSender.Messages = WebHookSender.Messages ?? new Dictionary<string, WebHookInfo>();

			// previous messages
			var filePath = Path.Combine(Global.StatusPath, "webhooks.json");
			if (File.Exists(filePath))
				try
				{
					var msgs = JArray.Parse(UtilityService.ReadTextFile(filePath));
					File.Delete(filePath);

					foreach (JObject msg in msgs)
					{
						var message = new WebHookMessage((msg["Message"] as JValue).Value as string);
						var time = (DateTime)(msg["Time"] as JValue).Value;
						var counters = (msg["Counters"] as JValue).Value.CastAs<int>();
						WebHookSender.Messages.Add(message.ID, new WebHookInfo() { Message = message, Time = time, Counters = counters });
					}
				}
				catch { }

			// new messages
			if (Directory.Exists(Global.WebHooksPath))
				UtilityService.GetFiles(Global.WebHooksPath, "*.msg")
					.ForEach(file =>
					{
						try
						{
							var msg = WebHookMessage.Load(file.FullName);
							WebHookSender.Messages.Add(msg.ID, new WebHookInfo() { Message = msg, Time = msg.SendingTime, Counters = 0 });
						}
						catch { }
						file.Delete();
					});
		}

		internal static void SaveMessages()
		{
			if (WebHookSender.Messages != null && WebHookSender.Messages.Count > 0)
				UtilityService.WriteTextFile(Path.Combine(Global.StatusPath, "webhooks.json"), WebHookSender.Messages.ToJArray(info => new JObject()
				{
					{ "Time", info.Time },
					{ "Counters", info.Counters },
					{ "Message", info.Message.Encrypted }
				}).ToString(Formatting.Indented));
			WebHookSender.Messages = null;
		}
		#endregion

		#region Send a message
		async Task SendMessageAsync(WebHookMessage msg, Action<string> onSuccess = null, Action<string, Exception> onError = null)
		{
			try
			{
				var query = string.Join("&", msg.Query.Select(info => info.Key + "=" + info.Value.UrlEncode()));
				await UtilityService.GetWebResponseAsync("POST", msg.EndpointURL + (!query.Equals("") ? "?" + query : ""), msg.Header, null, msg.Body, "application/json", 45, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)  VIEApps NGX WebHook Sender", null, null, null, Global.CancellationTokenSource.Token);
				onSuccess?.Invoke(msg.ID);
			}
			catch (OperationCanceledException) { }
			catch (Exception ex)
			{
				onError?.Invoke(msg.ID, ex);
			}
		}

		void OnSuccess(string id)
		{
			var msg = WebHookSender.Messages[id].Message;
			Global.WriteLog("The email has been sent" + "\r\n"
				+ "- ID: " + msg.ID + "\r\n"
				+ "- End-point: " + msg.EndpointURL, null, true, null, "webhook");
			WebHookSender.Messages.Remove(id);
		}

		void OnError(string id, Exception ex)
		{
			var msg = WebHookSender.Messages[id].Message;
			var log = "Error occurred while sending an email message" + "\r\n"
				+ "- ID: " + msg.ID + "\r\n"
				+ "- End-point: " + msg.EndpointURL
				+ "- Error: " + ex.Message + " [" + ex.GetType().ToString() + "]" + "\r\n\r\n";
			
			var counters = WebHookSender.Messages[id].Counters;
			if (counters > 4)
			{
				WebHookSender.Messages.Remove(id);
				log += "- Status: Remove from queue because its failed too much times";
			}
			else
			{
				var time = DateTime.Now.AddMinutes(1);
				if (counters == 1)
					time = DateTime.Now.AddMinutes(3);
				else if (counters == 2)
					time = DateTime.Now.AddMinutes(13);
				else if (counters > 2)
					time = DateTime.Now.AddMinutes(23 + ((counters - 2) * 3));

				WebHookSender.Messages[id].Time = time;
				WebHookSender.Messages[id].Counters = counters + 1;

				log += "- Status: Update queue to re-send at [" + time.ToDTString() + "]";
			}

			Global.WriteLog(log, ex, true, null, "webhook");
		}
		#endregion

		public async Task ProcessAsync()
		{
			// load messages
			WebHookSender.LoadMessages();

			// send messages
			await WebHookSender.Messages
				.Where(kvp => kvp.Value.Time <= DateTime.Now)
				.ForEachAsync((kvp, cancellationToken) => this.SendMessageAsync(kvp.Value.Message, this.OnSuccess, this.OnError))
				.ConfigureAwait(false);
		}
	}
}