namespace net.vieapps.Services.APIGateway
{
	partial class ManagementForm
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
			this.Services = new System.Windows.Forms.ListView();
			this.ServiceURI = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
			this.ServiceStatus = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
			this.ServiceName = new System.Windows.Forms.Label();
			this.Change = new System.Windows.Forms.Button();
			this.SuspendLayout();
			// 
			// Services
			// 
			this.Services.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.ServiceURI,
            this.ServiceStatus});
			this.Services.FullRowSelect = true;
			this.Services.GridLines = true;
			this.Services.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.Nonclickable;
			this.Services.Location = new System.Drawing.Point(12, 91);
			this.Services.Name = "Services";
			this.Services.Size = new System.Drawing.Size(1460, 744);
			this.Services.TabIndex = 0;
			this.Services.UseCompatibleStateImageBehavior = false;
			this.Services.View = System.Windows.Forms.View.Details;
			this.Services.SelectedIndexChanged += new System.EventHandler(this.Services_SelectedIndexChanged);
			// 
			// ServiceURI
			// 
			this.ServiceURI.Width = 600;
			// 
			// ServiceStatus
			// 
			this.ServiceStatus.Width = 100;
			// 
			// ServiceName
			// 
			this.ServiceName.AutoSize = true;
			this.ServiceName.Location = new System.Drawing.Point(12, 33);
			this.ServiceName.Name = "ServiceName";
			this.ServiceName.Size = new System.Drawing.Size(146, 25);
			this.ServiceName.TabIndex = 1;
			this.ServiceName.Text = "Service Name";
			// 
			// Change
			// 
			this.Change.Enabled = false;
			this.Change.Location = new System.Drawing.Point(1319, 21);
			this.Change.Name = "Change";
			this.Change.Size = new System.Drawing.Size(152, 48);
			this.Change.TabIndex = 2;
			this.Change.Text = "Start";
			this.Change.UseVisualStyleBackColor = true;
			this.Change.Click += new System.EventHandler(this.Change_Click);
			// 
			// ManagementForm
			// 
			this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.ClientSize = new System.Drawing.Size(1484, 847);
			this.Controls.Add(this.Change);
			this.Controls.Add(this.ServiceName);
			this.Controls.Add(this.Services);
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.MaximizeBox = false;
			this.MinimizeBox = false;
			this.Name = "ManagementForm";
			this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
			this.Text = "Business Services";
			this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.ServicesForm_FormClosing);
			this.ResumeLayout(false);
			this.PerformLayout();

		}

		#endregion

		private System.Windows.Forms.ListView Services;
		private System.Windows.Forms.Label ServiceName;
		private System.Windows.Forms.Button Change;
		private System.Windows.Forms.ColumnHeader ServiceURI;
		private System.Windows.Forms.ColumnHeader ServiceStatus;
	}
}