namespace net.vieapps.Services.APIGateway
{
	partial class ServicePresenter
	{
		/// <summary>
		/// Required designer variable.
		/// </summary>
		private System.ComponentModel.IContainer components = null;

		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		/// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
		protected override void Dispose(bool disposing)
		{
			if (disposing && (components != null))
			{
				components.Dispose();
			}
			base.Dispose(disposing);
		}

		#region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ServicePresenter));
			this.Logs = new System.Windows.Forms.TextBox();
			this.CommandLine = new System.Windows.Forms.TextBox();
			this.SuspendLayout();
			// 
			// Logs
			// 
			this.Logs.Location = new System.Drawing.Point(15, 58);
			this.Logs.Margin = new System.Windows.Forms.Padding(6);
			this.Logs.MaxLength = 0;
			this.Logs.Multiline = true;
			this.Logs.Name = "Logs";
			this.Logs.ReadOnly = true;
			this.Logs.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
			this.Logs.Size = new System.Drawing.Size(968, 624);
			this.Logs.TabIndex = 2;
			// 
			// CommandLine
			// 
			this.CommandLine.Location = new System.Drawing.Point(15, 15);
			this.CommandLine.Margin = new System.Windows.Forms.Padding(6);
			this.CommandLine.MaxLength = 0;
			this.CommandLine.Name = "CommandLine";
			this.CommandLine.ReadOnly = true;
			this.CommandLine.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
			this.CommandLine.Size = new System.Drawing.Size(968, 31);
			this.CommandLine.TabIndex = 1;
			// 
			// ServicePresenter
			// 
			this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.ClientSize = new System.Drawing.Size(998, 697);
			this.Controls.Add(this.CommandLine);
			this.Controls.Add(this.Logs);
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
			this.MaximizeBox = false;
			this.MinimizeBox = false;
			this.Name = "ServicePresenter";
			this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
			this.Text = "VIEApps API Gateway Router";
			this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.ServicePresenter_FormClosed);
			this.Load += new System.EventHandler(this.ServicePresenter_Load);
			this.ResumeLayout(false);
			this.PerformLayout();
		}
		#endregion

		private System.Windows.Forms.TextBox Logs;
		private System.Windows.Forms.TextBox CommandLine;
	}
}