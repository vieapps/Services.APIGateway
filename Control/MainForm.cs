using System;
using System.Windows.Forms;

namespace net.vieapps.Services.APIGateway
{
	public partial class MainForm : Form
	{
		string[] arguments = null;

		public MainForm(string[] args = null)
		{
			this.InitializeComponent();
			this.arguments = args;
		}

		void MainForm_Load(object sender, EventArgs args)
		{
			Global.Component.Start(this.arguments);
		}

		void MainForm_FormClosed(object sender, FormClosedEventArgs args)
		{
			Global.Component.Dispose();
		}

		void ManageServices_Click(object sender, EventArgs args)
		{
			
		}

		void ClearLogs_Click(object sender, EventArgs args)
		{
			this.Logs.Text = "";
		}

		public delegate void UpdateLogsDelegator(string logs);

		internal void UpdateLogs(string logs)
		{
			if (base.InvokeRequired)
				base.Invoke(new UpdateLogsDelegator(this.UpdateLogs), new object[] { logs });
			else
				try
				{
					this.Logs.AppendText(logs + "\r\n");
					this.Logs.SelectionStart = this.Logs.TextLength;
					this.Logs.ScrollToCaret();
				}
				catch { }
		}

		public delegate void UpdateServicesInfoDelegator(int available, int running);

		internal void UpdateServicesInfo(int available, int running)
		{
			if (base.InvokeRequired)
				base.Invoke(new UpdateServicesInfoDelegator(this.UpdateServicesInfo), new object[] { available, running });
			else
				try
				{
					this.ServicesInfo.Text = $"Available services: {available} - Running services: {running}";
				}
				catch { }
		}
	}
}