#region Related components
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Configuration;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class ManagementService : IManagementService
	{

		#region Constructor
		public ManagementService()
		{
#if DEBUG
			this._max = 3;
#else
			try
			{
				this._max = ConfigurationManager.AppSettings["MaxLogItems"].CastAs<int>();
			}
			catch
			{
				this._max = 10;
			}
#endif

			try
			{
				this._logsPath = ConfigurationManager.AppSettings["LogsPath"];
			}
			catch { }
			if (string.IsNullOrWhiteSpace(this._logsPath))
				this._logsPath = Directory.GetCurrentDirectory() + @"\logs";
			else if (this._logsPath.EndsWith(@"\"))
				this._logsPath = this._logsPath.Left(this._logsPath.Length - 1);
		}
		#endregion

		#region Working with logs
		Dictionary<string, Queue<string>> _logs = new Dictionary<string, Queue<string>>();
		int _max = 10;
		string _logsPath = "logs";

		public Task WriteLogAsync(string correlationID, string serviceName, string objectName, string log, string stack)
		{
			return this.WriteLogsAsync(correlationID, serviceName, objectName, new List<string>() { log }, stack);
		}

		public Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, string stack)
		{
			string path = serviceName.ToLower() + @"\" + serviceName.ToLower()
				+ (!string.IsNullOrWhiteSpace(objectName) && !serviceName.IsEquals(objectName) ? "." + objectName.ToLower() : "");

			if (!this._logs.TryGetValue(path, out Queue<string> queueOfLogs))
				lock (this._logs)
				{
					if (!this._logs.TryGetValue(path, out queueOfLogs))
					{
						queueOfLogs = new Queue<string>();
						this._logs.Add(path, queueOfLogs);
					}
				}

			logs.ForEach(log =>
			{
				queueOfLogs.Enqueue(correlationID + "\t" + DateTime.Now.ToString("HH:mm:ss.fff") + "\t" + log + (string.IsNullOrWhiteSpace(stack) ? "" : "\r\n\t" + stack + "\r\n"));
				if (!Global.AsService)
					Global.Form.UpdateLogs(correlationID + "\t" + DateTime.Now.ToString("HH:mm:ss.fff") + "\t" + log + (string.IsNullOrWhiteSpace(stack) ? "" : "\r\n\t" + stack + "\r\n"));
			});

			if (queueOfLogs.Count >= this._max)
				this.Flush(path, queueOfLogs);

			return Task.CompletedTask;
		}

		internal void Flush(string path, Queue<string> logs)
		{
			var logItems = new List<string>();
			while (logs.Count > 0)
				logItems.Add(logs.Dequeue());

			if (!Directory.Exists(this._logsPath))
				Directory.CreateDirectory(this._logsPath);

			var info = path.ToArray('\\');

			if (!Directory.Exists(this._logsPath + @"\" + info[0]))
				Directory.CreateDirectory(this._logsPath + @"\" + info[0]);

			UtilityService.WriteTextFile(this._logsPath + @"\" + info[0] + @"\" + DateTime.Now.ToString("yyyy-MM-dd-HH") + "." + info[1] + ".txt", logItems, true);
		}

		internal void FlushAll()
		{
			this._logs.ForEach(info =>
			{
				this.Flush(info.Key, info.Value);
			});
		}
		#endregion

	}
}