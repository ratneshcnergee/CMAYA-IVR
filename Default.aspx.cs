using System;
using System.Collections;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Xml.Linq;


public partial class _Default : System.Web.UI.Page
{

    Authentication AuthOBJ = new Authentication();
    CRMIVRIntegration ObjIVR = new CRMIVRIntegration();
    protected void Page_Load(object sender, EventArgs e)
    {

    }
    protected void Button1_Click(object sender, EventArgs e)
    {
        AuthOBJ.VendorCode = "WSU026";
        AuthOBJ.UserName = "NEWSSVIVR";
        AuthOBJ.Password = "$$1234#@$";

       lblmsg.Text = ObjIVR.CalltoCCStart("1010101010", "l.j", "1234", "11052015090521", AuthOBJ);
       lblmsg.Text = ObjIVR.CalltoCCStart("1010101020", "l.j", "1234", "11052015090521", AuthOBJ);

        /*API-1*/
     //   lblmsg.Text = ObjIVR.GetCustomerStatus("", "Kishor12", "16082016100521", AuthOBJ);

        /*API-4*/
      //  lblmsg.Text = ObjIVR.UpdateIVRCustomerDetails("8691997317", "16082016101021", AuthOBJ);

        /*API-2*/
        //lblmsg.Text = ObjIVR.IVREnquiry("8691997317", true, AuthOBJ);

        /*API-3*/
       // lblmsg.Text = ObjIVR.GenerateComplaint("8691997317", "OT", AuthOBJ);


        //lblmsg.Text = ObjIVR.CalltoCCStart(9347283532, 1234, 123, "10022014102132", AuthOBJ);
        //lblmsg.Text = ObjIVR.CalltoCCEND("9004094250", "1234", "1234", "11052015090521", AuthOBJ);


     //   lblmsg.Text = ObjIVR.GetCustomerInfo("", "Kishor12", "16082016100521", AuthOBJ);

    }
}
