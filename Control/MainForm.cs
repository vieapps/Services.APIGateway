using System;
using System.Linq;
using System.Threading.Tasks;
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
			Global.Component.Start(this.arguments, async () =>
			{
				await Task.Delay(567);
				if (Global.ServiceManager != null)
				{
					var services = Global.ServiceManager.GetAvailableBusinessServices();
					services.Select(kvp => kvp.Key).ToList().ForEach(name => services[name] = Global.ServiceManager.IsBusinessServiceRunning(name) ? "Yes" : "No");
					this.UpdateServicesInfo(services.Count, services.Where(kvp => kvp.Value.Equals("Yes")).Count());
				}
			});
		}

		void MainForm_FormClosed(object sender, FormClosedEventArgs args)
		{
			Global.Component.Dispose();
		}

		void ManageServices_Click(object sender, EventArgs args)
		{
			if (!Global.Component._status.Equals("Ready"))
				return;

			if (Global.ManagementForm == null)
				Global.ManagementForm = new ManagementForm();

			Global.ManagementForm.Initialize();
			Global.ManagementForm.Show();
			Global.ManagementForm.Focus();
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