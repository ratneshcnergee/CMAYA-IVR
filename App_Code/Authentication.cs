using System;
using System.Data;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Xml.Linq;

/// <summary>
/// Summary description for Authentication
/// </summary>
public class Authentication
{
    public Authentication()
    {
        //
        // TODO: Add constructor logic here
        //
    }
    private string _UserName;
    private string _Password;
    private string _VendorCode;
    public string UserName
    {
        get
        {
            return _UserName;
        }
        set
        {
            _UserName = value;
        }
    }
    public string Password
    {
        get
        {
            return _Password;
        }
        set
        {
            _Password = value;
        }
    }

    public string VendorCode
    {
        get
        {
            return _VendorCode;
        }
        set
        {
            _VendorCode = value;
        }
    }
}
