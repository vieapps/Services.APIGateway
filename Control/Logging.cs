#region Related components
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using System.IO;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class LoggingService : ILoggingService
	{
		ConcurrentDictionary<string, ConcurrentQueue<string>> _logs = new ConcurrentDictionary<string, ConcurrentQueue<string>>();
		int _max = 10;

		public LoggingService()
		{
#if DEBUG
			this._max = 3;
#else
			try
			{
				this._max = UtilityService.GetAppSetting("Logs:MaxItems", "13").CastAs<int>();
			}
			catch
			{
				this._max = 13;
			}
#endif
		}

		public Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, string stack = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			// prepare
			var prefix = (!string.IsNullOrWhiteSpace(serviceName) ? serviceName : "APIGateway").ToLower();
			var surfix = !string.IsNullOrWhiteSpace(serviceName) && !string.IsNullOrWhiteSpace(objectName) && !serviceName.IsEquals(objectName)
				? "." + objectName.ToLower()
				: "";

			var path = prefix + Path.DirectorySeparatorChar.ToString() + prefix + surfix;
			if (!this._logs.TryGetValue(path, out ConcurrentQueue<string> svcLogs))
				lock (this._logs)
				{
					if (!this._logs.TryGetValue(path, out svcLogs))
					{
						svcLogs = new ConcurrentQueue<string>();
						this._logs.TryAdd(path, svcLogs);
					}
				}

			// normal logs
			var formLogs = "";
			logs.ForEach(log =>
			{
				var info = DateTime.Now.ToString("HH:mm:ss.fff") + "\t" + correlationID + "     \t" + log;
				svcLogs.Enqueue(info);
				if (!Global.AsService)
					formLogs += (!formLogs.Equals("") ? "\r\n" : "") + info;
			});

			if (!string.IsNullOrWhiteSpace(stack))
			{
				svcLogs.Enqueue("==> Stack:" + "\r\n" + stack);
				if (!Global.AsService)
					formLogs += (!formLogs.Equals("") ? "\r\n" : "") + "==> Stack:" + "\r\n" + stack;
			}

			if (svcLogs.Count >= this._max)
				this.Flush(path, svcLogs);

			if (!Global.AsService && !formLogs.Equals(""))
				Global.MainForm.UpdateLogs("----- ["
					+ (!string.IsNullOrWhiteSpace(serviceName) ? serviceName.ToLower() : "APIGateway")
					+ (!string.IsNullOrWhiteSpace(objectName) ? "." + objectName.ToLower() : "")
					+ "] ----------" + "\r\n" + formLogs + "\r\n");

			// error logs
			if (!string.IsNullOrWhiteSpace(stack))
			{
				var errorLogs = new ConcurrentQueue<string>();
				logs.ForEach(log => errorLogs.Enqueue(DateTime.Now.ToString("HH:mm:ss.fff") + "\t" + correlationID + "     \t" + log));
				errorLogs.Enqueue("==> Stack:" + "\r\n" + stack);
				this.Flush(prefix + Path.DirectorySeparatorChar.ToString() + prefix + ".errors", errorLogs);
			}

			return Task.CompletedTask;
		}

		public Task WriteLogAsync(string correlationID, string serviceName, string objectName, string log, string stack = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			return this.WriteLogsAsync(correlationID, serviceName, objectName, new List<string>() { log }, stack, cancellationToken);
		}

		internal void WriteLogs(string correlationID, string serviceName, string objectName, List<string> logs, string stack = null)
		{
			Task.Run(async () =>
			{
				try
				{
					await this.WriteLogsAsync(correlationID, serviceName, objectName, logs, stack).ConfigureAwait(false);
				}
				catch { }
			}).ConfigureAwait(false);
		}

		internal void WriteLogs(string serviceName, string objectName, List<string> logs, string stack = null)
		{
			this.WriteLogs(UtilityService.NewUID, serviceName, objectName, logs, stack);
		}

		internal void WriteLog(string correlationID, string serviceName, string objectName, string log, string stack = null)
		{
			this.WriteLogs(correlationID, serviceName, objectName, new List<string>() { log }, stack);
		}

		internal void WriteLog(string serviceName, string objectName, string log, string stack = null)
		{
			this.WriteLogs(UtilityService.NewUID, serviceName, objectName, new List<string>() { log }, stack);
		}

		internal void Flush(string path, ConcurrentQueue<string> logs)
		{
			var lines = new List<string>();
			while (logs.TryDequeue(out string log))
				if (!string.IsNullOrWhiteSpace(log))
					lines.Add(log);

			var info = path.ToArray(Path.DirectorySeparatorChar);

			if (!Directory.Exists(Path.Combine(Global.LogsPath, info[0])))
				Directory.CreateDirectory(Path.Combine(Global.LogsPath, info[0]));

			UtilityService.WriteTextFile(Path.Combine(Global.LogsPath, info[0], DateTime.Now.ToString("yyyy-MM-dd-HH") + "." + info[1] + ".txt"), lines);
		}

		internal void FlushAll()
		{
			this._logs.ForEach(info => this.Flush(info.Key, info.Value));
		}
	}
}