#region Related components
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Configuration;
using System.IO;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class ManagementService : IManagementService
	{

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
				this._logsPath = UtilityService.GetAppSetting("LogsPath");
			}
			catch { }

			if (string.IsNullOrWhiteSpace(this._logsPath))
				this._logsPath = Directory.GetCurrentDirectory() + @"\logs";
			else if (this._logsPath.EndsWith(@"\"))
				this._logsPath = this._logsPath.Left(this._logsPath.Length - 1);
		}

		#region Working with logs
		Dictionary<string, Queue<string>> _logs = new Dictionary<string, Queue<string>>();
		int _max = 10;
		string _logsPath = "logs";

		public Task WriteLogAsync(string correlationID, string serviceName, string objectName, string log, string simpleStack = null, string fullStack = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			return this.WriteLogsAsync(correlationID, serviceName, objectName, new List<string>() { log }, simpleStack, fullStack, cancellationToken);
		}

		public Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, string simpleStack = null, string fullStack = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			string prefix = !string.IsNullOrWhiteSpace(serviceName)
				? serviceName.ToLower()
				: "apigateway";

			string surfix = !string.IsNullOrWhiteSpace(serviceName) && !string.IsNullOrWhiteSpace(objectName) && !serviceName.IsEquals(objectName)
				? "." + objectName.ToLower()
				: "";

			string path = prefix + @"\" + prefix + surfix;

			if (!this._logs.TryGetValue(path, out Queue<string> svcLogs))
				lock (this._logs)
				{
					if (!this._logs.TryGetValue(path, out svcLogs))
					{
						svcLogs = new Queue<string>();
						this._logs.Add(path, svcLogs);
					}
				}

			if (!string.IsNullOrWhiteSpace(simpleStack) || !string.IsNullOrWhiteSpace(fullStack))
				svcLogs.Enqueue("----------------------------------------------");

			var formLogs = "";
			logs.ForEach(log =>
			{
				var info = DateTime.Now.ToString("HH:mm:ss.fff") + "\t" + correlationID + "     \t" + log;
				svcLogs.Enqueue(info);
				if (!Global.AsService)
					formLogs += (!formLogs.Equals("") ? "\r\n" : "") + info;
			});

			if (!string.IsNullOrWhiteSpace(simpleStack))
				svcLogs.Enqueue("\r\n" + "==> Stack:" + "\r\n" + simpleStack);

			if (!string.IsNullOrWhiteSpace(fullStack))
				svcLogs.Enqueue("\r\n" + "==> Stack (Full):" + "\r\n" + fullStack);

			if (!string.IsNullOrWhiteSpace(simpleStack) || !string.IsNullOrWhiteSpace(fullStack))
				svcLogs.Enqueue("----------------------------------------------");

			if (svcLogs.Count >= this._max)
				this.Flush(path, svcLogs);

			if (!Global.AsService && !formLogs.Equals(""))
			{
				if (!string.IsNullOrWhiteSpace(simpleStack))
					formLogs += "\r\n" + "==> Stack:" + "\r\n" + simpleStack;
				formLogs = "----- ["
					+ (!string.IsNullOrWhiteSpace(serviceName) ? serviceName.ToLower() : "APIGateway")
					+ (!string.IsNullOrWhiteSpace(objectName) ? "." + objectName.ToLower() : "")
					+ "] ----------" + "\r\n" + formLogs + "\r\n";
				Global.Form.UpdateLogs(formLogs);
			}

			return Task.CompletedTask;
		}

		internal void Flush(string path, Queue<string> logs)
		{
			var lines = new List<string>();
			while (logs.Count > 0)
				lines.Add(logs.Dequeue());

			if (!Directory.Exists(this._logsPath))
				Directory.CreateDirectory(this._logsPath);

			var info = path.ToArray('\\');

			if (!Directory.Exists(this._logsPath + @"\" + info[0]))
				Directory.CreateDirectory(this._logsPath + @"\" + info[0]);

			UtilityService.WriteTextFile(this._logsPath + @"\" + info[0] + @"\" + DateTime.Now.ToString("yyyy-MM-dd-HH") + "." + info[1] + ".txt", lines);
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