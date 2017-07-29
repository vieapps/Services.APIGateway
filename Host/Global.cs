#region Related components
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
#endregion

namespace net.vieapps.Services.APIGateway
{
	internal static class Global
	{
		internal static bool AsService = true;
		internal static ServiceComponent Component = null;
		internal static MainForm Form = null;

		#region Working with logs
		static EventLog EventLog = null;

		internal static void InitializeLog()
		{
			if (Global.EventLog == null)
			{
				string logName = "Application";
				string logSource = "VIEApps API Gateway";

				if (!EventLog.SourceExists(logSource))
					EventLog.CreateEventSource(logSource, logName);

				Global.EventLog = new EventLog(logSource)
				{
					Source = logSource,
					Log = logName
				};
			}
		}

		internal static void DisposeLog()
		{
			Global.EventLog.Close();
			Global.EventLog.Dispose();
		}

		internal static void WriteLog(string log, Exception ex = null)
		{
			string msg = log + (ex != null ? "\r\n\r\n" + "Message: " + ex.Message + " [" + ex.GetType().ToString() + "]\r\n\r\n" + "Details: " + ex.StackTrace : "");
			if (Global.AsService)
				Global.EventLog.WriteEntry(msg, ex != null ? EventLogEntryType.Error : EventLogEntryType.Information);
			else
			{
				//Program.Form.UpdateLogs(msg);
			}
		}
		#endregion

		#region Working with processes
		[DllImport("kernel32.dll")]
		private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

		[DllImport("kernel32.dll")]
		private static extern bool QueryFullProcessImageName(IntPtr hprocess, int dwFlags, StringBuilder lpExeName, out int size);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool CloseHandle(IntPtr hHandle);

		[Flags]
		private enum ProcessAccessFlags : uint
		{
			All = 0x1f0fff,
			CreateThread = 2,
			DupHandle = 0x40,
			QueryInformation = 0x400,
			ReadControl = 0x20000,
			SetInformation = 0x200,
			Synchronize = 0x100000,
			Terminate = 1,
			VMOperation = 8,
			VMRead = 0x10,
			VMWrite = 0x20
		}

		internal static List<Tuple<int, string>> GetProcesses(string processExeFilename)
		{
			if (string.IsNullOrWhiteSpace(processExeFilename))
				return null;

			var processes = new List<Tuple<int, string>>();
			foreach (var process in Process.GetProcesses())
			{
				var id = process.Id;
				var handler = Global.OpenProcess(ProcessAccessFlags.QueryInformation, false, id);
				if (handler != IntPtr.Zero)
					try
					{
						var pathBuilder = new StringBuilder(0x400);
						var capacity = pathBuilder.Capacity;
						if (Global.QueryFullProcessImageName(handler, 0, pathBuilder, out capacity))
						{
							string processName = pathBuilder.ToString();
							if (processName.ToLower().EndsWith(processExeFilename.ToLower()))
								processes.Add(new Tuple<int, string>(id, processName));
						}
					}
					catch { }
					finally
					{
						Global.CloseHandle(handler);
					}
			}

			return processes;
		}

		internal static int GetProcessID(string processExeFilename, int excludedPID = 0)
		{
			if (string.IsNullOrWhiteSpace(processExeFilename))
				return -1;

			var process = Global.GetProcesses(processExeFilename).FirstOrDefault(info => excludedPID > 0 ? !info.Item1.Equals(excludedPID) : true);
			return process == null
				? -1
				: process.Item1;
		}
		#endregion

	}
}
