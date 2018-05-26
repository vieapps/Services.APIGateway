#region Related components
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public partial class ManagementForm : Form
	{
		public ManagementForm() => this.InitializeComponent();

		void ServicesForm_FormClosing(object sender, FormClosingEventArgs e)
		{
			Program.PrepareServices();
			Program.MainForm.UpdateServicesInfo();
			this.Hide();
			e.Cancel = true;
		}

		void Services_SelectedIndexChanged(object sender, EventArgs e) => this.OnSelected();

		void Change_Click(object sender, EventArgs e) => this.OnChange();

		public delegate void InitializeDelegator();

		internal void Initialize()
		{
			if (base.InvokeRequired)
				base.Invoke(new InitializeDelegator(this.Initialize), new object[] { });
			else
			{
				this.ServiceURI.Text = "Service URI";
				this.ServiceStatus.Text = "Status";
				this.Services.MultiSelect = false;
				this.DisplayServices();
			}
		}

		public delegate void DisplayServicesDelegator();

		void DisplayServices()
		{
			if (base.InvokeRequired)
				base.Invoke(new DisplayServicesDelegator(this.DisplayServices), new object[] { });
			else
			{
				Program.PrepareServices();
				Program.MainForm.UpdateServicesInfo();
				this.Services.Items.Clear();
				Program.Services.OrderBy(kvp => kvp.Key).ForEach(kvp => this.Services.Items.Add(new ListViewItem(new[] { kvp.Key, kvp.Value ? "Running" : "Stopped" })));
			}
		}

		public delegate void OnSelectedDelegator();

		void OnSelected()
		{
			if (base.InvokeRequired)
				base.Invoke(new OnSelectedDelegator(this.OnSelected), new object[] { });
			else
			{
				if (this.Services.SelectedItems == null || this.Services.SelectedItems.Count < 1)
					this.ServiceName.Visible = this.Change.Enabled = false;
				else
				{
					var name = this.Services.SelectedItems[0].Text;
					this.ServiceName.Visible = this.Change.Enabled = true;
					this.ServiceName.Text = $"Service: [{name}]";
					this.Change.Text = Program.GetServiceState(name.ToArray('.').Last()) ? "Stop" : "Start";
				}
			}
		}

		void OnChange()
		{
			if (this.Services.SelectedItems == null || this.Services.SelectedItems.Count < 1)
				return;

			var name = this.Services.SelectedItems[0].Text.ToArray('.').Last();

			if (Program.GetServiceState(name))
				Task.Run(() =>
				{
					try
					{
						Program.GetServiceManager().StopBusinessService(name);
						Program.SetServiceState(name, false);
					}
					catch (Exception ex)
					{
						Global.OnError($"Cannot stop the business service: {ex.Message}", ex);
					}
				})
				.ContinueWith(task => this.DisplayServices(), TaskContinuationOptions.OnlyOnRanToCompletion)
				.ContinueWith(task => this.OnSelected(), TaskContinuationOptions.OnlyOnRanToCompletion)
				.ConfigureAwait(false);

			else
				Task.Run(() =>
				{
					try
					{
						Program.GetServiceManager().StartBusinessService(name, $"/usr:{Environment.UserName.UrlEncode()} /hst:{Environment.MachineName.UrlEncode()} /pfn:{RuntimeInformation.FrameworkDescription.UrlEncode()} /pfo:{RuntimeInformation.OSDescription.Trim().UrlEncode()}");
						Program.SetServiceState(name, true);
					}
					catch (Exception ex)
					{
						Global.OnError($"Cannot start the business service: {ex.Message}", ex);
					}
				})
				.ContinueWith(task => this.DisplayServices(), TaskContinuationOptions.OnlyOnRanToCompletion)
				.ContinueWith(task => this.OnSelected(), TaskContinuationOptions.OnlyOnRanToCompletion)
				.ConfigureAwait(false);
		}
	}
}