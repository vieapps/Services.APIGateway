#region Related components
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public partial class ManagementForm : Form
	{
		public ManagementForm() => this.InitializeComponent();

		void ServicesForm_FormClosing(object sender, FormClosingEventArgs e)
		{
			this.Hide();
			e.Cancel = true;
		}

		void Services_SelectedIndexChanged(object sender, EventArgs e) => this.OnSelected();

		void Change_Click(object sender, EventArgs e) => this.OnChange();

		internal void Initialize()
		{
			this.ServiceURI.Text = "Service URI";
			this.ServiceStatus.Text = "Status";
			this.Services.MultiSelect = false;

			this.RefreshServices();
			this.DisplayServices();
		}

		public Dictionary<string, bool> BusinessServices { get; private set; } = new Dictionary<string, bool>();

		internal void RefreshServices()
		{
			this.BusinessServices.Clear();
			var serviceManager = Program.GetServiceManager();
			if (serviceManager != null)
				try
				{
					serviceManager.GetAvailableBusinessServices().ForEach(kvp =>
					{
						this.BusinessServices.Add($"net.vieapps.services.{kvp.Key}", serviceManager.IsBusinessServiceRunning(kvp.Key));
					});
				}
				catch { }
		}

		void DisplayServices()
		{
			this.Services.Items.Clear();
			this.BusinessServices.OrderBy(kvp => kvp.Key).ForEach(kvp =>
			{
				this.Services.Items.Add(new ListViewItem(new[] { kvp.Key, kvp.Value ? "Running" : "Stopped" }));
			});
			Program.MainForm.UpdateServicesInfo(this.BusinessServices.Count, this.BusinessServices.Where(kvp => kvp.Value).Count());
		}

		void OnSelected()
		{
			if (this.Services.SelectedItems == null || this.Services.SelectedItems.Count < 1)
			{
				this.ServiceName.Visible = this.Change.Enabled = false;
				return;
			}

			var name = this.Services.SelectedItems[0].Text;
			this.ServiceName.Visible = this.Change.Enabled = true;
			this.ServiceName.Text = $"Service: [{name}]";
			this.Change.Text = this.BusinessServices[name] ? "Stop" : "Start";
		}

		void OnChange()
		{
			if (this.Services.SelectedItems == null || this.Services.SelectedItems.Count < 1)
				return;

			var name = this.Services.SelectedItems[0].Text;
			var serviceManager = Program.GetServiceManager();

			if (this.BusinessServices[name])
				Task.Run(() =>
				{
					try
					{
						serviceManager.StopBusinessService(name.ToArray('.').Last());
						this.BusinessServices[name] = false;
					}
					catch (Exception ex)
					{
						Global.OnError($"Cannot stop the business service: {ex.Message}", ex);
					}
				})
				.ContinueWith(task => this.DisplayServices(), TaskContinuationOptions.OnlyOnRanToCompletion)
				.ConfigureAwait(false);

			else
				Task.Run(() =>
				{
					try
					{
						serviceManager.StartBusinessService(name.ToArray('.').Last());
						this.BusinessServices[name] = true;
					}
					catch (Exception ex)
					{
						Global.OnError($"Cannot start the business service: {ex.Message}", ex);
					}
				})
				.ContinueWith(task => this.DisplayServices(), TaskContinuationOptions.OnlyOnRanToCompletion)
				.ConfigureAwait(false);
		}
	}
}