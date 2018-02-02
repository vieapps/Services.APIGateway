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
		ConcurrentQueue<string> _debugLogs = new ConcurrentQueue<string>();
		bool _logsAreFlushing = false, _debugLogsAreFlushing = false;
		int _max = 13;

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

		#region Write logs
		public Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, string stack = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			// prepare
			var time = DateTime.Now.ToString("HH:mm:ss.fff");
			var prefix = (!string.IsNullOrWhiteSpace(serviceName) ? serviceName : "APIGateway").ToLower();
			var surfix = !string.IsNullOrWhiteSpace(objectName) && !objectName.IsEquals(serviceName)
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
				var info = time + "\t" + correlationID + "     \t" + log;
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
				Task.Run(async () =>
				{
					await this.FlushLogsAsync(path, svcLogs, cancellationToken).ConfigureAwait(false);
				}).ConfigureAwait(false);

			if (!Global.AsService && !formLogs.Equals(""))
				Global.MainForm.UpdateLogs("----- ["
					+ (!string.IsNullOrWhiteSpace(serviceName) ? serviceName : "APIGateway")
					+ (!string.IsNullOrWhiteSpace(objectName) ? "." + objectName : "")
					+ "] ----------" + "\r\n" + formLogs + "\r\n");

			// error logs
			if (!string.IsNullOrWhiteSpace(stack))
			{
				var errorLogs = new ConcurrentQueue<string>();
				logs.ForEach(log => errorLogs.Enqueue(time + "\t" + correlationID + "     \t" + log));
				errorLogs.Enqueue("==> Stack:" + "\r\n" + stack);
				Task.Run(async () =>
				{
					await this.FlushLogsAsync(prefix + Path.DirectorySeparatorChar.ToString() + prefix + ".errors", errorLogs, cancellationToken).ConfigureAwait(false);
				}).ConfigureAwait(false);
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
				await this.WriteLogsAsync(correlationID, serviceName, objectName, logs, stack, Global.CancellationTokenSource.Token).ConfigureAwait(false);
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

		internal async Task FlushLogsAsync(string path, ConcurrentQueue<string> logs, CancellationToken cancellationToken = default(CancellationToken))
		{
			while (this._logsAreFlushing)
				await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);

			this._logsAreFlushing = true;
			try
			{
				var lines = new List<string>();
				while (logs.TryDequeue(out string log))
					if (!string.IsNullOrWhiteSpace(log))
						lines.Add(log);

				var info = path.ToArray(Path.DirectorySeparatorChar);
				if (!Directory.Exists(Path.Combine(Global.LogsPath, info[0])))
					Directory.CreateDirectory(Path.Combine(Global.LogsPath, info[0]));

				await UtilityService.WriteTextFileAsync(Path.Combine(Global.LogsPath, info[0], DateTime.Now.ToString("yyyy-MM-dd_HH") + "." + info[1] + ".txt"), lines, true, null, cancellationToken).ConfigureAwait(false);
			}
			catch { }
			this._logsAreFlushing = false;
		}
		#endregion

		#region Write debug logs
		public void WriteDebugLogs(string correlationID, string serviceName, List<string> logs)
		{
			var time = DateTime.Now.ToString("HH:mm:ss.fff");
			var service = serviceName ?? "Unknown";
			logs?.ForEach(log => this._debugLogs.Enqueue($"{time}\t{correlationID}\t{service}\t{log}"));
			if (this._debugLogs.Count >= this._max)
				Task.Run(async () =>
				{
					await this.FlushDebugLogsAsync().ConfigureAwait(false);
				}).ConfigureAwait(false);
		}

		public void WriteDebugLogs(string correlationID, string serviceName, string logs)
		{
			this.WriteDebugLogs(correlationID, serviceName, new List<string>() { logs });
		}

		public Task WriteDebugLogsAsync(string correlationID, string serviceName, List<string> logs, CancellationToken cancellationToken = default(CancellationToken))
		{
			var time = DateTime.Now.ToString("HH:mm:ss.fff");
			var service = serviceName ?? "Unknown";
			logs?.ForEach(log => this._debugLogs.Enqueue($"{time}\t{correlationID}\t{service}\t{log}"));
			if (this._debugLogs.Count >= this._max)
				Task.Run(async () =>
				{
					await this.FlushDebugLogsAsync(cancellationToken).ConfigureAwait(false);
				}).ConfigureAwait(false);
			return Task.CompletedTask;
		}

		public Task WriteDebugLogsAsync(string correlationID, string serviceName, string logs, CancellationToken cancellationToken = default(CancellationToken))
		{
			return this.WriteDebugLogsAsync(correlationID, serviceName, new List<string>() { logs }, cancellationToken);
		}

		internal async Task FlushDebugLogsAsync(CancellationToken cancellationToken = default(CancellationToken))
		{
			while (this._debugLogsAreFlushing)
				await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);

			this._debugLogsAreFlushing = true;
			try
			{
				var lines = new List<string>();
				while (this._debugLogs.TryDequeue(out string log))
					if (!string.IsNullOrWhiteSpace(log))
						lines.Add(log);

				var filename = DateTime.Now.Minute > 49
					? "6"
					: DateTime.Now.Minute > 39
						? "5"
						: DateTime.Now.Minute > 29
							? "4"
							: DateTime.Now.Minute > 19
								? "3"
								: DateTime.Now.Minute > 9
									? "2"
									: "1";

				await UtilityService.WriteTextFileAsync(Path.Combine(Global.LogsPath, $"{DateTime.Now.ToString("yyyy-MM-dd_HH")}-{filename}.debug.txt"), lines, true, null, cancellationToken).ConfigureAwait(false);
			}
			catch { }
			this._debugLogsAreFlushing = false;
		}
		#endregion

		internal void FlushAllLogs()
		{
			Task.Run(async () =>
			{
				await this.FlushDebugLogsAsync().ConfigureAwait(false);
				await this._logs.ForEachAsync((kvp, cancellationToken) => this.FlushLogsAsync(kvp.Key, kvp.Value), CancellationToken.None, true, false).ConfigureAwait(false);
			}).ConfigureAwait(false);
		}
	}
}