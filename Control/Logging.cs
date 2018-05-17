#region Related components
using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public class LoggingService : ILoggingService
	{

		#region Properties
		static string _LogsPath = null;

		internal static string LogsPath => LoggingService._LogsPath ?? (LoggingService._LogsPath = Global.GetPath("Path:Logs", "logs"));

		readonly ConcurrentDictionary<string, ConcurrentQueue<string>> _logs = new ConcurrentDictionary<string, ConcurrentQueue<string>>();
		readonly CancellationTokenSource _cancellationTokenSource;
		readonly int _max = 13;
		bool _logsAreFlushing = false;
		#endregion

		public LoggingService(CancellationToken cancellationToken = default(CancellationToken))
		{
			this._cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

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

		~LoggingService()
		{
			this._cancellationTokenSource.Dispose();
		}

		void WriteLogs(string correlationID, string serviceName, string objectName, List<string> logs, string stack = null)
		{
			// prepare
			var time = DateTime.Now.ToString("HH:mm:ss.fff");
			var name = (!string.IsNullOrWhiteSpace(serviceName) ? serviceName : "APIGateway").ToLower();
			var sufix = !string.IsNullOrWhiteSpace(objectName) && !objectName.IsEquals(serviceName) ? "." + objectName.ToLower() : "";

			if (!this._logs.TryGetValue(name + sufix, out ConcurrentQueue<string> svcLogs))
			{
				svcLogs = new ConcurrentQueue<string>();
				this._logs.TryAdd(name + sufix, svcLogs);
			}

			// normal logs
			var messages = "";
			var errorLogs = new ConcurrentQueue<string>();
			logs?.Where(log => !string.IsNullOrWhiteSpace(log)).ForEach(log =>
			{
				svcLogs.Enqueue($"{time}\t{correlationID}\t{log}");
				if (!string.IsNullOrWhiteSpace(stack))
					errorLogs.Enqueue($"{time}\t{correlationID}\t{log}");
				messages += (!messages.Equals("") ? "\r\n" : "") + $"{time}\t{correlationID}\t{log}";
			});

			if (!string.IsNullOrWhiteSpace(stack))
			{
				svcLogs.Enqueue($"==> Stack:\r\n{stack}");
				errorLogs.Enqueue($"==> Stack:\r\n{stack}");
				messages += (!messages.Equals("") ? "\r\n" : "") + $"==> Stack:\r\n{stack}";
			}

			// flush into files
			if (svcLogs.Count >= this._max)
				Task.Run(() => this.FlushLogsAsync(name + sufix, svcLogs)).ConfigureAwait(false);

			if (errorLogs.Count > 0)
				Task.Run(() => this.FlushLogsAsync(name + ".errors", errorLogs)).ConfigureAwait(false);

			Global.OnLogsUpdated(serviceName, messages);
		}

		public Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, string stack = null, CancellationToken cancellationToken = default(CancellationToken))
			=> UtilityService.ExecuteTask(() => this.WriteLogs(correlationID, serviceName, objectName, logs, stack), cancellationToken);

		public Task WriteLogAsync(string correlationID, string serviceName, string objectName, string log, string stack = null, CancellationToken cancellationToken = default(CancellationToken))
			=> this.WriteLogsAsync(correlationID, serviceName, objectName, new List<string>() { log }, stack, cancellationToken);

		async Task FlushLogsAsync(string name, ConcurrentQueue<string> logs)
		{
			while (this._logsAreFlushing)
				await Task.Delay(UtilityService.GetRandomNumber(123, 456)).ConfigureAwait(false);

			this._logsAreFlushing = true;
			var lines = new List<string>();
			while (logs.TryDequeue(out string log))
				lines.Add(log);
			if (lines.Count > 0)
				try
				{
					var filename = $"{DateTime.Now.ToString("yyyyMMdd")}_{name}.{DateTime.Now.ToString("HH")}.txt";
					await UtilityService.WriteTextFileAsync(Path.Combine(LoggingService.LogsPath, filename), lines, true, null, this._cancellationTokenSource.Token).ConfigureAwait(false);
				}
				catch { }
			this._logsAreFlushing = false;
		}

		internal void FlushAllLogs()
			=> Task.Run(() => this._logs.ForEachAsync((kvp, cancellationToken) => this.FlushLogsAsync(kvp.Key, kvp.Value), CancellationToken.None, true, false)).ConfigureAwait(false);
	}
}