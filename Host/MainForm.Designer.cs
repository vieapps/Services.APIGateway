namespace net.vieapps.Services.APIGateway
{
	partial class MainForm
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
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
			this.ManageServices = new System.Windows.Forms.Button();
			this.ClearLogs = new System.Windows.Forms.Button();
			this.Logs = new System.Windows.Forms.TextBox();
			this.ServicesInfo = new System.Windows.Forms.Label();
			this.SuspendLayout();
			// 
			// ManageServices
			// 
			this.ManageServices.Location = new System.Drawing.Point(12, 12);
			this.ManageServices.Name = "ManageServices";
			this.ManageServices.Size = new System.Drawing.Size(246, 70);
			this.ManageServices.TabIndex = 0;
			this.ManageServices.Text = "Manage services";
			this.ManageServices.UseVisualStyleBackColor = true;
			this.ManageServices.Click += new System.EventHandler(this.ManageServices_Click);
			// 
			// ClearLogs
			// 
			this.ClearLogs.Location = new System.Drawing.Point(1436, 12);
			this.ClearLogs.Name = "ClearLogs";
			this.ClearLogs.Size = new System.Drawing.Size(246, 70);
			this.ClearLogs.TabIndex = 1;
			this.ClearLogs.Text = "Clear logs";
			this.ClearLogs.UseVisualStyleBackColor = true;
			this.ClearLogs.Click += new System.EventHandler(this.ClearLogs_Click);
			// 
			// Logs
			// 
			this.Logs.Location = new System.Drawing.Point(12, 97);
			this.Logs.MaxLength = 0;
			this.Logs.Multiline = true;
			this.Logs.Name = "Logs";
			this.Logs.ReadOnly = true;
			this.Logs.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
			this.Logs.Size = new System.Drawing.Size(1671, 858);
			this.Logs.TabIndex = 2;
			// 
			// ServicesInfo
			// 
			this.ServicesInfo.AutoSize = true;
			this.ServicesInfo.Location = new System.Drawing.Point(295, 35);
			this.ServicesInfo.Name = "ServicesInfo";
			this.ServicesInfo.Size = new System.Drawing.Size(30, 25);
			this.ServicesInfo.TabIndex = 3;
			this.ServicesInfo.Text = "...";
			// 
			// MainForm
			// 
			this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.ClientSize = new System.Drawing.Size(1694, 967);
			this.Controls.Add(this.ServicesInfo);
			this.Controls.Add(this.Logs);
			this.Controls.Add(this.ClearLogs);
			this.Controls.Add(this.ManageServices);
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
			this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
			this.MaximizeBox = false;
			this.MinimizeBox = false;
			this.Name = "MainForm";
			this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
			this.Text = "VIEApps API Gateway";
			this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.MainForm_FormClosed);
			this.Load += new System.EventHandler(this.MainForm_Load);
			this.ResumeLayout(false);
			this.PerformLayout();

		}

		#endregion

		private System.Windows.Forms.Button ManageServices;
		private System.Windows.Forms.Button ClearLogs;
		private System.Windows.Forms.TextBox Logs;
		private System.Windows.Forms.Label ServicesInfo;
	}
}