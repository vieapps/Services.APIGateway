using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace net.vieapps.Services.APIGateway
{
	public partial class MainForm : Form
	{
		public MainForm(string[] args = null)
		{
			this.InitializeComponent();
			this.arguments = args;
		}

		string[] arguments = null;

		void MainForm_Load(object sender, EventArgs e)
		{
			Global.Component.Start(this.arguments);
		}

		void MainForm_FormClosed(object sender, FormClosedEventArgs e)
		{
			Global.Component.Dispose();
		}
	}
}