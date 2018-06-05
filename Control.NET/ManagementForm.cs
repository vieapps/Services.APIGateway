#region Related components
using System;
using System.Linq;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Collections.Generic;

using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.APIGateway
{
	public partial class ManagementForm : Form
	{
		public ManagementForm()
		{
			this.InitializeComponent();
			this.ServiceURI.Text = "Service URI";
			this.ServiceStatus.Text = "Status";
			this.Services.MultiSelect = false;
		}

		void ServicesForm_FormClosing(object sender, FormClosingEventArgs e)
		{
			Program.MainForm.UpdateServicesInfo();
			this.SetControlsState(false, false);
			this.Selected = null;
			this.Hide();
			e.Cancel = true;
		}

		void Services_SelectedIndexChanged(object sender, EventArgs e) => this.OnSelected();

		void Change_Click(object sender, EventArgs e) => this.OnChange();

		public delegate void DisplayServicesDelegator();

		internal void DisplayServices()
		{
			if (base.InvokeRequired)
				base.Invoke(new DisplayServicesDelegator(this.DisplayServices), new object[] { });
			else
			{
				Program.Refresh();
				Program.MainForm.UpdateServicesInfo();

				var controllers = Program.Controller.GetAvailableControllers().ToDictionary(controller => controller.ID);
				this.Services.Items.Clear();
				Program.Services.OrderBy(kvp => kvp.Key).ForEach(kvp =>
				{
					var uri = kvp.Key;
					if (kvp.Value.Count > 1)
					{
						var isRunning = kvp.Value.IsRunning();
						var itemOfAll = new ListViewItem(new[] { $"{uri} - {kvp.Value.Count:#,##0} instance(s)", isRunning ? "Running" : "Stopped", "", uri })
						{
							UseItemStyleForSubItems = false
						};
						itemOfAll.SubItems[0].Font = new Font(this.Services.Font, FontStyle.Bold);
						itemOfAll.SubItems[1].ForeColor = isRunning ? SystemColors.WindowText : Color.Red;
						this.Services.Items.Add(itemOfAll);
						kvp.Value.ForEach(info =>
						{
							if (controllers.TryGetValue(info.Key, out ControllerInfo controller))
							{
								var itemOfController = new ListViewItem(new[] { $"  {controller.Host} - {controller.Platform}", info.Value ? "Running" : "Stopped", controller.ID, uri })
								{
									UseItemStyleForSubItems = false
								};
								itemOfController.SubItems[1].ForeColor = info.Value ? SystemColors.WindowText : Color.Red;
								this.Services.Items.Add(itemOfController);
							}
						});
					}
					else
					{
						var controllerID = kvp.Value.Count > 0 ? kvp.Value.ElementAt(0).Key : null;
						if (controllers.TryGetValue(controllerID, out ControllerInfo controller))
						{
							var isRunning = kvp.Value.IsRunning();
							var listItem = new ListViewItem(new[] { uri, kvp.Value.IsRunning() ? "Running" : "Stopped", controller.ID, uri })
							{
								UseItemStyleForSubItems = false
							};
							listItem.SubItems[1].ForeColor = isRunning ? SystemColors.WindowText : Color.Red;
							this.Services.Items.Add(listItem);
						}
					}
				});
			}
		}

		public delegate void SetControlsStateDelegator(bool state, bool servicesApplied);

		internal void SetControlsState(bool state, bool servicesApplied = true)
		{
			if (base.InvokeRequired)
				base.Invoke(new SetControlsStateDelegator(this.SetControlsState), new object[] { state, servicesApplied });
			else
			{
				this.ServiceName.Visible = this.Change.Enabled = state;
				if (servicesApplied)
					this.Services.Enabled = state;
			}
		}

		public delegate void DisplaySelectedInfoDelegator();

		void DisplaySelectedInfo()
		{
			if (base.InvokeRequired)
				base.Invoke(new DisplaySelectedInfoDelegator(this.DisplaySelectedInfo), new object[] { });
			else
			{
				var isRunning = this.AreInstancesSelected
					? Program.Services.TryGetValue(this.Selected.SubItems[3].Text, out Dictionary<string, bool> instances)
						? instances.IsRunning()
						: false
					: this.Selected.SubItems[1].Text.Equals("Running");

				this.ServiceName.Visible = this.Change.Enabled = true;
				this.Change.Text = isRunning ? "Stop" : "Start";
				this.ServiceName.Text = $"{this.Selected.SubItems[3].Text}";
				if (this.AreInstancesSelected)
					this.ServiceName.Text += " - All instances";
				else
				{
					var controllerID = this.Selected.SubItems[2].Text;
					var controllers = Program.Controller.GetAvailableControllers();
					var controller = controllers.FirstOrDefault(c => c.ID == controllerID);
					if (controller != null)
						this.ServiceName.Text += $" @ {controller.Host} [{controller.Platform}]";
				}
			}
		}

		internal ListViewItem Selected { get; set; } = null;

		bool AreInstancesSelected
			=> this.Selected == null
				? false
				: this.Selected.SubItems[2].Text.Equals("");

		public delegate void OnSelectedDelegator();

		void OnSelected()
		{
			if (base.InvokeRequired)
				base.Invoke(new OnSelectedDelegator(this.OnSelected), new object[] { });
			else
			{
				if (this.Services.SelectedItems == null || this.Services.SelectedItems.Count < 1)
					this.SetControlsState(false, false);
				else
				{
					this.Selected = this.Services.SelectedItems[0];
					this.DisplaySelectedInfo();
				}
			}
		}

		public delegate void UpdateSelectedDelegator();

		void UpdateSelected()
		{
			if (base.InvokeRequired)
				base.Invoke(new UpdateSelectedDelegator(this.UpdateSelected), new object[] { });
			else
			{
				var controllers = Program.Controller.GetAvailableControllers();
				var uri = this.Selected.SubItems[3].Text;
				var name = uri.ToArray('.').Last();
				if (this.AreInstancesSelected)
				{
					var isRunning = false;
					controllers.ForEach(controller =>
					{
						var serviceManager = Program.GetServiceManager(controller.ID);
						if (serviceManager != null)
						{
							isRunning = serviceManager.IsBusinessServiceRunning(name);
							Program.SetServiceState(controller.ID, name, isRunning);
							ListViewItem listItem = null;
							foreach (ListViewItem item in this.Services.Items)
								if (item.SubItems[2].Text.Equals(controller.ID) && item.SubItems[3].Text.Equals(uri))
								{
									listItem = item;
									break;
								}
							if (listItem != null)
							{
								listItem.SubItems[1].Text = isRunning ? "Running" : "Stopped";
								listItem.SubItems[1].ForeColor = isRunning ? SystemColors.WindowText : Color.Red;
							}
						}
					});

					isRunning = Program.Services.TryGetValue(this.Selected.SubItems[3].Text, out Dictionary<string, bool> instances)
						? instances.IsRunning()
						: false;
					this.Selected.SubItems[1].Text = isRunning ? "Running" : "Stopped";
					this.Selected.SubItems[1].ForeColor = isRunning ? SystemColors.WindowText : Color.Red;
				}
				else
				{
					var controllerID = this.Selected.SubItems[2].Text;
					var serviceManager = Program.GetServiceManager(controllerID);
					if (serviceManager != null)
					{
						var isRunning = serviceManager.IsBusinessServiceRunning(name);
						Program.SetServiceState(controllerID, name, isRunning);
						this.Selected.SubItems[1].Text = isRunning ? "Running" : "Stopped";
						this.Selected.SubItems[1].ForeColor = isRunning ? SystemColors.WindowText : Color.Red;
					}
				}
				this.SetControlsState(true);
				this.DisplaySelectedInfo();
			}
		}

		void Start(string controllerID, string name)
		{
			try
			{
				Program.GetServiceManager(controllerID).StartBusinessService(name, Program.Controller.GetServiceArguments().Replace("/", "/call-"));
			}
			catch (Exception ex)
			{
				Global.OnError($"Cannot start the business service: {ex.Message}", ex);
			}
		}

		void Start(string name)
		{
			Task.WaitAll(Program.Controller.GetAvailableControllers().Select(controller => Task.Run(() => this.Start(controller.ID, name))).ToArray());
		}

		void Stop(string controllerID, string name)
		{
			try
			{
				Program.GetServiceManager(controllerID).StopBusinessService(name);
			}
			catch (Exception ex)
			{
				Global.OnError($"Cannot stop the business service: {ex.Message}", ex);
			}
		}

		void Stop(string name)
		{
			Task.WaitAll(Program.Controller.GetAvailableControllers().Select(controller => Task.Run(() => this.Stop(controller.ID, name))).ToArray());
		}

		void OnChange()
		{
			if (this.Selected == null)
				return;

			var uri = this.Selected.SubItems[3].Text;
			var isRunning = this.AreInstancesSelected
				? Program.Services.TryGetValue(uri, out Dictionary<string, bool> instances)
					? instances.IsRunning()
					: false
				: this.Selected.SubItems[1].Text.Equals("Running");

			if (this.AreInstancesSelected)
			{
				var confirm = MessageBox.Show($"Are you sure you want to {(isRunning ? "stop" : "start")} all instances of \"{uri}\" service?", "Are you sure", MessageBoxButtons.YesNo);
				if (confirm == DialogResult.No)
					return;
			}

			var name = uri.ToArray('.').Last();
			this.SetControlsState(false);
			if (this.AreInstancesSelected)
			{
				if (isRunning)
					Task.Run(() => this.Stop(name)).ConfigureAwait(false);
				else
					Task.Run(() => this.Start(name)).ConfigureAwait(false);
			}
			else
			{
				var controllerID = this.Selected.SubItems[2].Text;
				if (isRunning)
					Task.Run(() => this.Stop(controllerID, name)).ConfigureAwait(false);
				else
					Task.Run(() => this.Start(controllerID, name)).ConfigureAwait(false);
			}
			this.SetControlsState(true);
		}

		public delegate void UpdateInfoDelegator(string controllerID, string uri, string state);

		internal void UpdateInfo(string controllerID, string uri, string state)
		{
			if (base.InvokeRequired)
				base.Invoke(new UpdateInfoDelegator(this.UpdateInfo), new object[] { controllerID, uri, state });
			else
			{
				ListViewItem listItem = null;
				foreach (ListViewItem item in this.Services.Items)
					if (item.SubItems[2].Text.Equals(controllerID) && item.SubItems[3].Text.Equals(uri))
					{
						listItem = item;
						break;
					}

				if (listItem != null)
				{
					listItem.SubItems[1].Text = state;
					listItem.SubItems[1].ForeColor = state.IsEquals("Running") ? SystemColors.WindowText : Color.Red;
				}

				foreach (ListViewItem item in this.Services.Items)
					if (item.SubItems[2].Text.Equals("") && item.SubItems[3].Text.Equals(uri))
					{
						listItem = item;
						break;
					}

				if (listItem != null && Program.Services.TryGetValue(uri, out Dictionary<string, bool> instances))
				{
					var isRunning = instances.IsRunning();
					listItem.SubItems[1].Text = isRunning ? "Running" : "Stopped";
					listItem.SubItems[1].ForeColor = isRunning ? SystemColors.WindowText : Color.Red;
				}

				if (this.Selected != null)
					this.UpdateSelected();
			}
		}
	}
}