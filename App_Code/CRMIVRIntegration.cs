using System;
using System.Linq;
using System.Web;
using System.Web.Services;
using System.Web.Services.Protocols;
using System.Xml.Linq;
using System.Data;
using System.Data.SqlClient;
using System.Web.Security;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IO;
using System.Text;


[WebService(Namespace = "http://tempuri.org/")]
[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
// To allow this Web Service to be called from script, using ASP.NET AJAX, uncomment the following line. 
//[System.Web.Script.Services.ScriptService]
public class CRMIVRIntegration : System.Web.Services.WebService
{
    string strReturnStatus = "";
    string ConnectionString = "";
    int MemberId = 0;
    int AreaID = 0;
    int statusid = 0;
    int ComplaintId = 0;
    bool isold = false;
    string Tickeno = "";
    SqlConnection con = new SqlConnection();
    DateTime dtCallDate = new DateTime();
    DataTable dtGetMemberId = new DataTable();
    DataTable dtGetTicketnumber = new DataTable();
    DataTable dtGetMemberComplaintNo = new DataTable();
    DataTable dtGetMemberComplaintnumber = new DataTable();
    DataTable dtGetstatusid = new DataTable();
    DataTable dtGetComplaintId = new DataTable();

    public CRMIVRIntegration()
    {

        //Uncomment the following line if using designed components 
        //InitializeComponent(); 
    }


    public static class StringCipher
    {
        //         string encryptedstring = StringCipher.Encrypt(plaintext, password);
        //string decryptedstring = StringCipher.Decrypt(encryptedstring, password);
        // This constant is used to determine the keysize of the encryption algorithm in bits.
        // We divide this by 8 within the code below to get the equivalent number of bytes.
        private const int Keysize = 256;
        static string CurrentCode = "qazD5qazi4qazl5qaze3qazs0qazh0qazB9qazh2qazo0qazi9qazrqaz";
        // This constant determines the number of iterations for the password bytes generation function.
        private const int DerivationIterations = 1000;

        public static string Decrypt(string cipherText)
        {
            string passPhrase = CurrentCode;
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations);
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }

        private static byte[] Generate256BitsOfRandomEntropy()
        {
            var randomBytes = new byte[32]; // 32 Bytes will give us 256 bits.
            var rngCsp = new RNGCryptoServiceProvider();
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
        public static string EncryptKey(string clearText)
        {
            string EncryptionKey = CurrentCode;
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return clearText;
        }
        public static string DecryptKey(string cipherText)
        {
            string EncryptionKey = CurrentCode;
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }


    }


    [WebMethod]
    private string Authentication(Authentication Authobj)
    {
        string ConnectionString = StringCipher.Decrypt(System.Configuration.ConfigurationManager.ConnectionStrings["GlobalMaster"].ConnectionString);
        SqlConnection con = new SqlConnection(ConnectionString);
        string conStr = "";
        DataSet dsConn = new DataSet();
        con.Open();
        string mySQL = "SELECT wsu.WSUserCode, wsu.WSUserLoginId, wsu.WSUserPassword, CASE WHEN wsu.IsActive = 1 AND " +
                " IsDeactivated = 0 THEN 1 ELSE 0 END AS IsActive, cm.ClientDBLocation, cm.ClientDB, cm.ClientDBUser, " +
                " cm.ClientDBPass FROM WebServiceUsers AS wsu INNER JOIN ClientMaster AS cm ON wsu.clientID = cm.clientID " +
                " WHERE (wsu.WSUserCode = '" + Authobj.VendorCode + "') AND (wsu.WSUserLoginId = '" + Authobj.UserName + "') " +
                " AND (wsu.WSUserPassword = '" + Authobj.Password + "')";
        SqlCommand cmd = new SqlCommand(mySQL, con);
        SqlDataAdapter ad = new SqlDataAdapter(cmd);
        ad.Fill(dsConn);
        con.Close();
        if (dsConn.Tables[0].Rows.Count == 1 && Convert.ToBoolean(dsConn.Tables[0].Rows[0]["IsActive"]))
        {

            conStr = System.Configuration.ConfigurationManager.ConnectionStrings["ConStr"].ConnectionString;
            conStr = string.Format(conStr, dsConn.Tables[0].Rows[0]["ClientDBLocation"].ToString(), dsConn.Tables[0].Rows[0]["ClientDB"].ToString(),
                dsConn.Tables[0].Rows[0]["ClientDBUser"].ToString(), dsConn.Tables[0].Rows[0]["ClientDBPass"].ToString());
            return conStr;
        }
        else
            return "";



    }


    [WebMethod]
    public string CalltoCCStart(string CallerId, string ExtensionNo, string TrunkNo, string CallStart, Authentication Authobj)
    //public string CalltoCCStart(string CallerId, string ExtensionNo, string CallStart, Authentication Authobj)
    {

        string strReturnStatus = "";
        string ConnectionString = Authentication(Authobj);
        SqlConnection con = new SqlConnection();
        DateTime dtCallDate = new DateTime();
        DataTable dt = new DataTable();
        if (ConnectionString != "")
        {
            try
            {
                con = new SqlConnection(ConnectionString);

                if (CallStart == null || CallStart.Trim() == "" || CallStart.Trim().Length != 14)
                {
                    strReturnStatus = "Invalid date Received...";
                }
                else
                {
                    dt = SqlHelper.ExecuteDataset(con, "tblCustMemberInfo_Insert", CallerId, "0", 0, false, DBNull.Value, DBNull.Value, "C").Tables[0];
                    if (dt.Rows.Count == 0)
                    {
                        //Convert date string into  date format
                        string strCallDate = CallStart.Substring(2, 2) + "/";
                        strCallDate += CallStart.Substring(0, 2) + "/";
                        strCallDate += CallStart.Substring(4, 4) + " ";
                        strCallDate += CallStart.Substring(8, 2) + ":";
                        strCallDate += CallStart.Substring(10, 2) + ":";
                        strCallDate += CallStart.Substring(12, 2);
                        dtCallDate = Convert.ToDateTime(strCallDate);
                        //if (Convert.ToInt64(ExtensionNo) > 0 && Convert.ToInt64(CallerId) > 0)
                        if (ExtensionNo !="" && Convert.ToInt64(CallerId) > 0)
                        {

                            SqlCommand cmd = new SqlCommand("tblCustMemberInfo_Insert", con);
                            cmd.CommandType = CommandType.StoredProcedure;
                            cmd.Parameters.Add("@CallerId", SqlDbType.VarChar).Value = CallerId;
                            cmd.Parameters.Add("@ExtensionNo", SqlDbType.VarChar).Value = ExtensionNo;
                            cmd.Parameters.Add("@TrunkNo", SqlDbType.BigInt).Value = Convert.ToInt64(0);
                            cmd.Parameters.Add("@IsAttended", SqlDbType.Bit).Value = 0;
                            cmd.Parameters.Add("@CallStart", SqlDbType.DateTime).Value = dtCallDate;
                            cmd.Parameters.Add("@CallEnd", SqlDbType.DateTime).Value = DBNull.Value;
                            cmd.Parameters.Add("@Param", SqlDbType.Char).Value = "I";
                            con.Open();
                            int i = cmd.ExecuteNonQuery();
                            if (i > 0)
                            {
                                //Success
                                strReturnStatus = "Successful...";
                            }
                            else
                            {
                                //Fail Not Inserted
                                strReturnStatus = "CRM Server not Reachable...";
                            }
                        }
                        else
                        {
                            //Invalid Extension Or Callorid 
                            strReturnStatus = "Invalid Extension OR CallerId...";
                        }
                    }
                    else
                    {

                    }
                }
            }
            catch
            {
                //DataBase Error: DB Error
                strReturnStatus = "Error: Please Contact To Administrator...";
            }
            finally
            {
                con.Close();
                con.Dispose();
            }
        }
        else
        {
            //authentication failed
            strReturnStatus = "Authentication Fail, Please check login credentials...";
        }
        return strReturnStatus;
    }


    [WebMethod]
    public string CalltoCCEND(string CallerId, string ExtensionNo, string TrunkNo, string CallEnd, Authentication Authobj)
    {

        string strReturnStatus = "";
        string ConnectionString = Authentication(Authobj);
        SqlConnection con = new SqlConnection();
        DateTime dtEndDate = new DateTime();
        if (ConnectionString != "")
        {
            try
            {
                con = new SqlConnection(ConnectionString);
                if (CallEnd == null || CallEnd.Trim() == "" || CallEnd.Trim().Length != 14)
                {
                    strReturnStatus = "Invalid date Received...";
                }
                else
                {
                    //Convert date string into  date format
                    string strEndDate = CallEnd.Substring(2, 2) + "/";
                    strEndDate += CallEnd.Substring(0, 2) + "/";
                    strEndDate += CallEnd.Substring(4, 4) + " ";
                    strEndDate += CallEnd.Substring(8, 2) + ":";
                    strEndDate += CallEnd.Substring(10, 2) + ":";
                    strEndDate += CallEnd.Substring(12, 2);
                    dtEndDate = Convert.ToDateTime(strEndDate);
                    if (Convert.ToInt64(ExtensionNo) > 0 && Convert.ToInt64(CallerId) > 0)
                    {

                        SqlCommand cmd = new SqlCommand("tblCustMemberInfo_Insert", con);
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.Add("@CallerId", SqlDbType.BigInt).Value = Convert.ToInt64(CallerId);
                        cmd.Parameters.Add("@ExtensionNo", SqlDbType.BigInt).Value = Convert.ToInt64(ExtensionNo);
                        cmd.Parameters.Add("@TrunkNo", SqlDbType.BigInt).Value = Convert.ToInt64(0);
                        cmd.Parameters.Add("@IsAttended", SqlDbType.Bit).Value = 0;
                        cmd.Parameters.Add("@CallStart", SqlDbType.DateTime).Value = DBNull.Value;
                        cmd.Parameters.Add("@CallEnd", SqlDbType.DateTime).Value = dtEndDate;
                        cmd.Parameters.Add("@Param", SqlDbType.Char).Value = "U";
                        con.Open();
                        int i = cmd.ExecuteNonQuery();
                        if (i == 1)
                        {
                            //Success
                            strReturnStatus = "Successful...";
                        }
                        else if (i == 0)
                        {
                            //No Update on database
                            strReturnStatus = "Invalid Extension OR CallerId...";
                        }
                        else
                        {
                            //Error
                            strReturnStatus = "CRM Server not Reachable...";
                        }
                    }
                    else
                    {
                        //Invalid Extension Or Callorid 
                        strReturnStatus = "Invalid Extension OR CallerId...";
                    }
                }


            }
            catch
            {
                //DataBase Error: DB Error
                strReturnStatus = "Error: Please Contact To Administrator...";
            }
            finally
            {
                con.Close();
                con.Dispose();
            }
        }
        else
        {
            //authentication failed
            strReturnStatus = "Authentication Fail, Please check login credentials...";
        }
        return strReturnStatus;
    }

    /*API-1*/
    /* GetCustomerStatus  */
    [WebMethod]
    public string GetCustomerStatus(string MobileNo,string MemberLoginID, string StartDatetime, Authentication Authobj)
    {
        ConnectionString = Authentication(Authobj);

        if (ConnectionString != "")
        {
            try
            {
                con = new SqlConnection(ConnectionString);

                if (StartDatetime == null || StartDatetime.Trim() == "" || StartDatetime.Trim().Length != 14)
                {
                    strReturnStatus = "Invalid date Received...";
                }
                else
                {
                    dtGetMemberId = SqlHelper.ExecuteDataset(con, "IVRCustomerDetails_insert", 0, DBNull.Value, DBNull.Value, 0, 0, MobileNo, "A",MemberLoginID).Tables[0];
                    if (dtGetMemberId != null && dtGetMemberId.Rows.Count > 0)
                    {

                        MemberId = Convert.ToInt32(dtGetMemberId.Rows[0]["MemberId"]);


                    }
                    else
                    {
                        MemberId = 0;

                    }

                    if (MemberId == 0)
                    {
                        isold = false;
                    }
                    else
                    {
                        isold = true;
                    }

                    if (isold == true)
                    {
                        dtGetMemberComplaintNo = SqlHelper.ExecuteDataset(con, "IVRCustomerDetails_insert", MemberId, DBNull.Value, DBNull.Value, 0, 0, MobileNo, "B",MemberLoginID).Tables[0];
                        if (dtGetMemberComplaintNo != null && dtGetMemberComplaintNo.Rows.Count > 0)
                        {
                            Tickeno = Convert.ToString(dtGetMemberComplaintNo.Rows[0]["MemberComplaintNo"]);
                        }
                        else
                        {
                            Tickeno = "";
                        }
                    }
                    //Convert date string into  date format
                    string strCallDate = StartDatetime.Substring(2, 2) + "/";
                    strCallDate += StartDatetime.Substring(0, 2) + "/";
                    strCallDate += StartDatetime.Substring(4, 4) + " ";
                    strCallDate += StartDatetime.Substring(8, 2) + ":";
                    strCallDate += StartDatetime.Substring(10, 2) + ":";
                    strCallDate += StartDatetime.Substring(12, 2);
                    dtCallDate = Convert.ToDateTime(strCallDate);
                    SqlCommand Sqlcmd = new SqlCommand("IVRCustomerDetails_insert", con);
                    Sqlcmd.CommandType = CommandType.StoredProcedure;

                    Sqlcmd.Parameters.Add("@Memberid", SqlDbType.BigInt).Value = Convert.ToInt64(MemberId);
                    Sqlcmd.Parameters.Add("@StartDatetime", SqlDbType.DateTime).Value = dtCallDate;
                    Sqlcmd.Parameters.Add("@Enddatetime", SqlDbType.DateTime).Value = DBNull.Value;
                    Sqlcmd.Parameters.Add("@IsOld", SqlDbType.Bit).Value = isold;
                    Sqlcmd.Parameters.Add("@IsCallOpen", SqlDbType.Bit).Value = 0;
                    Sqlcmd.Parameters.Add("@Where", SqlDbType.Char).Value = MobileNo;
                    Sqlcmd.Parameters.Add("@Param", SqlDbType.Char).Value = "C";
                    Sqlcmd.Parameters.Add("@MemberLoginID", SqlDbType.Char).Value = MemberLoginID;
                    con.Open();
                    int i = Sqlcmd.ExecuteNonQuery();
                    if (isold == false)
                    {
                        //new memberid
                        strReturnStatus = "0";
                    }
                    else if (isold == true && Tickeno == "")
                    {
                        //exists memberid
                        strReturnStatus = "1";
                    }
                    else if (isold == true && Tickeno != "")
                    {
                        //exists memberid and ticke no open
                        strReturnStatus = Tickeno;
                    }

                    else
                    {
                        strReturnStatus = "CMAYA Server not Reachable...";
                    }
                }
            }
            catch
            {
                //DataBase Error: DB Error
                strReturnStatus = "CMAYA Server not Reachable...";
            }
            finally
            {
                con.Close();
                con.Dispose();
            }
        }
        else
        {
            //authentication failed
            strReturnStatus = "Authentication Fail, Please check login credentials...";
        }
        return strReturnStatus;
    }


    /*API-2*/
    /* Register new enq - RegisterENewEnq */
    [WebMethod]
    public string RegisterNewEnquiry(string MobileNo,string MemberLoginID, Authentication Authobj)
    {
        ConnectionString = Authentication(Authobj);
        if (ConnectionString != "")
        {
            try
            {
                con = new SqlConnection(ConnectionString);

                dtGetMemberId = SqlHelper.ExecuteDataset(con, "IVRCustomerDetails_insert", 0, DBNull.Value, DBNull.Value, 0, 0, MobileNo, "A", MemberLoginID).Tables[0];
                if (dtGetMemberId.Rows.Count == 0)
                {

                    dtGetTicketnumber = SqlHelper.ExecuteDataset(con, "Sequence_GetSet", "IVREnquiry", 1).Tables[1];
                    if (dtGetTicketnumber != null && dtGetTicketnumber.Rows.Count > 0)
                    {
                        Tickeno = dtGetTicketnumber.Rows[0]["Ticketnumber"].ToString();
                    }
                    /*insert online enquiry*/
                    SqlCommand Sqlcmd = new SqlCommand("OnlineEnquiryInsert_SP", con);
                    Sqlcmd.CommandType = CommandType.StoredProcedure;
                    Sqlcmd.CommandType = CommandType.StoredProcedure;
                    Sqlcmd.Parameters.Add("@CustomerName", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@Dob", SqlDbType.DateTime).Value = DBNull.Value;
                    Sqlcmd.Parameters.Add("@PrimaryMobile", SqlDbType.Char).Value = MobileNo;
                    Sqlcmd.Parameters.Add("@SecondaryMobile", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@emailid", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@ConnectionType", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@Country", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@State", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@City", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@Area", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@SubArea", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@FullAddress", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@ContactDate", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@Contacthour_From", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@ContactHour_To", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@Comment", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@CreateDate", SqlDbType.DateTime).Value = DBNull.Value;
                    Sqlcmd.Parameters.Add("@FilledFrom", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@HostIp", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@HostName", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@ClientSystemIP", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@Gateway", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@UsedDeviceOS", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@DeviceName", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@DNS", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@MovedBy", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@MoveToEnquiry", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@TitleId", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@MiddleName", SqlDbType.Char).Value = "";
                    Sqlcmd.Parameters.Add("@LastName", SqlDbType.Char).Value = "";


                    /*Get Max Id in online enquiry*/





                    /*insert ivr enquiry*/
                    SqlCommand Sqlcmdd = new SqlCommand("GetIVREnquiry_insert", con);
                    Sqlcmdd.CommandType = CommandType.StoredProcedure;
                    Sqlcmdd.Parameters.Add("@EnquiryId", SqlDbType.BigInt).Value = 0;
                    Sqlcmdd.Parameters.Add("@ticketNo", SqlDbType.Char).Value = Tickeno;
                    Sqlcmdd.Parameters.Add("@mobileNo", SqlDbType.Char).Value = MobileNo;
                    Sqlcmdd.Parameters.Add("@CreatedOn", SqlDbType.DateTime).Value = DateTime.Today;
                    Sqlcmdd.Parameters.Add("@Param", SqlDbType.Char).Value = "A";




                    /*insert IVRCustomerDetails*/
                    SqlCommand cmdd = new SqlCommand("IVRCustomerDetails_insert", con);
                    cmdd.CommandType = CommandType.StoredProcedure;
                    cmdd.Parameters.Add("@Memberid", SqlDbType.BigInt).Value = Convert.ToInt64(0);
                    cmdd.Parameters.Add("@StartDatetime", SqlDbType.DateTime).Value = DateTime.Today;
                    cmdd.Parameters.Add("@Enddatetime", SqlDbType.DateTime).Value = DBNull.Value;
                    cmdd.Parameters.Add("@IsOld", SqlDbType.Bit).Value = 0;
                    cmdd.Parameters.Add("@IsCallOpen", SqlDbType.Bit).Value = 0;
                    cmdd.Parameters.Add("@Where", SqlDbType.Char).Value = MobileNo;
                    cmdd.Parameters.Add("@Param", SqlDbType.Char).Value = "C";
                    cmdd.Parameters.Add("@MemberLoginID", SqlDbType.Char).Value = MemberLoginID;
                    con.Open();
                    int OnlineEnquiryRsult = Sqlcmd.ExecuteNonQuery();
                    int CustomerDetailsResult = cmdd.ExecuteNonQuery();
                    int GetIVREnquiryResult = Sqlcmdd.ExecuteNonQuery();
                    // con.Open();

                    if (GetIVREnquiryResult > 0 && CustomerDetailsResult > 0 && OnlineEnquiryRsult > 0)
                    {
                        strReturnStatus = Tickeno;
                    }

                }

                else
                {
                    strReturnStatus = "Mobile Number Not Present...";
                }

            }


            catch
            {
                //DataBase Error: DB Error
                strReturnStatus = "CMAYA Server not Reachable...";
            }
            finally
            {
                con.Close();
                con.Dispose();
            }
        }
        else
        {
            //authentication failed
            strReturnStatus = "Authentication Fail, Please check login credentials...";
        }
        return strReturnStatus;
    }



    /*API-3*/
    /* Register Complaint  */

    [WebMethod]
    public string RegisterComplaint(string MobileNo,string MemberLoginId, string ComplaintType, Authentication Authobj)
    {
        ConnectionString = Authentication(Authobj);

        if (ConnectionString != "")
        {
            try
            {
                con = new SqlConnection(ConnectionString);
                dtGetMemberId = SqlHelper.ExecuteDataset(con, "IVRCustomerDetails_insert", 0, DBNull.Value, DBNull.Value, 0, 0, MobileNo, "A", MemberLoginId).Tables[0];
                if (dtGetMemberId != null && dtGetMemberId.Rows.Count > 0)
                {
                    MemberId = Convert.ToInt32(dtGetMemberId.Rows[0]["MemberId"]);
                    AreaID = Convert.ToInt32(dtGetMemberId.Rows[0]["AreaID"]);

                    dtGetMemberComplaintNo = SqlHelper.ExecuteDataset(con, "IVRCustomerDetails_insert", MemberId, DBNull.Value, DBNull.Value, 0, 0, "", "E").Tables[0];
                    if (dtGetMemberComplaintNo.Rows.Count == 0)
                    {
                        string MemberComplaintnumber = "";
                        string GetMemberComplaintnumber = Convert.ToString(SqlHelper.ExecuteScalar(con, "NewSequence_GetSet", "MemberComplaintId", 1, AreaID));
                        if (GetMemberComplaintnumber != "")
                        {
                            MemberComplaintnumber = GetMemberComplaintnumber;
                        }

                        dtGetstatusid = SqlHelper.ExecuteDataset(con, "PD_StatusMaster_Select", 0, "B").Tables[0];
                        if (dtGetstatusid != null && dtGetstatusid.Rows.Count > 0)
                        {
                            statusid = Convert.ToInt32(dtGetstatusid.Rows[0]["statusid"]);
                        }

                        dtGetComplaintId = SqlHelper.ExecuteDataset(con, "IVRComplaintsPrefix", ComplaintType, "P").Tables[0];
                        if (dtGetComplaintId != null && dtGetComplaintId.Rows.Count > 0)
                        {
                            ComplaintId = Convert.ToInt32(dtGetComplaintId.Rows[0]["ComplaintId"]);
                        }


                        /*insert MemberComplaints*/
                        SqlCommand Sqlcmd = new SqlCommand("MemberComplaints_Add", con);
                        Sqlcmd.CommandType = CommandType.StoredProcedure;
                        Sqlcmd.Parameters.Add("@MemberComplaintNo", SqlDbType.Char).Value = MemberComplaintnumber;
                        Sqlcmd.Parameters.Add("@MemberId", SqlDbType.BigInt).Value = MemberId;
                        Sqlcmd.Parameters.Add("@UserId", SqlDbType.BigInt).Value = 0;
                        Sqlcmd.Parameters.Add("@ComplaintDate", SqlDbType.DateTime).Value = DateTime.Today;
                        Sqlcmd.Parameters.Add("@statusId", SqlDbType.BigInt).Value = statusid;
                        Sqlcmd.Parameters.Add("@ComplaintId", SqlDbType.BigInt).Value = ComplaintId;
                        Sqlcmd.Parameters.Add("@AreaId", SqlDbType.BigInt).Value = AreaID;
                        Sqlcmd.Parameters.Add("@ForService", SqlDbType.Char).Value = "IVR";
                        Sqlcmd.Parameters.Add("@Param", SqlDbType.Char).Value = "I";


                        /*insert MemberComplaintFollowUps*/
                        SqlCommand Sqlcommand = new SqlCommand("MemberComplaintFollowUps_Add", con);
                        Sqlcommand.CommandType = CommandType.StoredProcedure;
                        Sqlcommand.Parameters.Add("@MemberComplaintNo", SqlDbType.Char).Value = MemberComplaintnumber;
                        Sqlcommand.Parameters.Add("@CreatedBy", SqlDbType.BigInt).Value = 0;
                        Sqlcommand.Parameters.Add("@CreatedDate", SqlDbType.DateTime).Value = DateTime.Today;
                        Sqlcommand.Parameters.Add("@AssignTo", SqlDbType.BigInt).Value = 0;
                        Sqlcommand.Parameters.Add("@TeamId", SqlDbType.BigInt).Value = 0;
                        Sqlcommand.Parameters.Add("@TeamHeadId", SqlDbType.BigInt).Value = 0;
                        Sqlcommand.Parameters.Add("@Comments", SqlDbType.Char).Value = "";
                        Sqlcommand.Parameters.Add("@StatusId", SqlDbType.BigInt).Value = statusid;




                        con.Open();
                        int GetMemberComplaintsResult = Sqlcmd.ExecuteNonQuery();
                        int GetMemberComplaintFollowUp = Sqlcommand.ExecuteNonQuery();

                        if (GetMemberComplaintsResult > 0 && GetMemberComplaintFollowUp > 0)
                        {
                            strReturnStatus = "Complaint Saved successfully...";
                        }


                    }


                    else
                    {

                        string Complaintnumber = Convert.ToString(dtGetMemberComplaintNo.Rows[0]["membercomplaintno"]);


                        dtGetstatusid = SqlHelper.ExecuteDataset(con, "PD_StatusMaster_Select", 0, "C").Tables[0];
                        if (dtGetstatusid != null && dtGetstatusid.Rows.Count > 0)
                        {
                            statusid = Convert.ToInt32(dtGetstatusid.Rows[0]["statusid"]);
                        }

                        /*update MemberComplaints*/
                        SqlCommand Sqlcmdd = new SqlCommand("MemberComplaints_Add", con);
                        Sqlcmdd.CommandType = CommandType.StoredProcedure;
                        Sqlcmdd.Parameters.Add("@MemberComplaintNo", SqlDbType.Char).Value = Complaintnumber;
                        Sqlcmdd.Parameters.Add("@MemberId", SqlDbType.BigInt).Value = MemberId;
                        Sqlcmdd.Parameters.Add("@UserId", SqlDbType.BigInt).Value = 0;
                        Sqlcmdd.Parameters.Add("@ComplaintDate", SqlDbType.DateTime).Value = DateTime.Today;
                        Sqlcmdd.Parameters.Add("@statusId", SqlDbType.BigInt).Value = statusid;
                        Sqlcmdd.Parameters.Add("@ComplaintId", SqlDbType.BigInt).Value = 0;
                        Sqlcmdd.Parameters.Add("@AreaId", SqlDbType.BigInt).Value = 0;
                        Sqlcmdd.Parameters.Add("@ForService", SqlDbType.Char).Value = "";
                        Sqlcmdd.Parameters.Add("@Param", SqlDbType.Char).Value = "U";


                        /*insert MemberComplaintFollowUps*/
                        SqlCommand Sqlcd = new SqlCommand("MemberComplaintFollowUps_Add", con);
                        Sqlcd.CommandType = CommandType.StoredProcedure;
                        Sqlcd.Parameters.Add("@MemberComplaintNo", SqlDbType.Char).Value = Complaintnumber;
                        Sqlcd.Parameters.Add("@CreatedBy", SqlDbType.BigInt).Value = 0;
                        Sqlcd.Parameters.Add("@CreatedDate", SqlDbType.DateTime).Value = DateTime.Today;
                        Sqlcd.Parameters.Add("@AssignTo", SqlDbType.BigInt).Value = 0;
                        Sqlcd.Parameters.Add("@TeamId", SqlDbType.BigInt).Value = 0;
                        Sqlcd.Parameters.Add("@TeamHeadId", SqlDbType.BigInt).Value = 0;
                        Sqlcd.Parameters.Add("@Comments", SqlDbType.Char).Value = "";
                        Sqlcd.Parameters.Add("@StatusId", SqlDbType.BigInt).Value = statusid;




                        con.Open();
                        int MemberComplaintResult = Sqlcmdd.ExecuteNonQuery();
                        int MemberComplaintFollowUpResult = Sqlcd.ExecuteNonQuery();

                        if (MemberComplaintResult > 0 && MemberComplaintFollowUpResult > 0)
                        {
                            strReturnStatus = "Complaint Saved successfully...";
                        }


                    }

                }

                else
                {

                    strReturnStatus = "Mobile Number not Present...";

                }
            }
            catch
            {
                strReturnStatus = "CMAYA Server not Reachable...";
            }
            finally
            {
                con.Close();
                con.Dispose();
            }

        }
        else
        {
            //authentication failed
            strReturnStatus = "Authentication Fail, Please check login credentials...";
        }

        return strReturnStatus;
    }


    /*API-4*/



    /* Add new method : getCustomerInfo  */
    [WebMethod]
    public string GetCustomerInfo(string MobileNo, string MemberLoginID, string StartDatetime, Authentication Authobj)
    {
         ConnectionString = Authentication(Authobj);

         if (ConnectionString != "")
         {
             try
             {
                 con = new SqlConnection(ConnectionString);
                 if (StartDatetime == null || StartDatetime.Trim() == "" || StartDatetime.Trim().Length != 14)
                 {
                     strReturnStatus = "Invalid date Received...";
                 }
                 else
                 {
                     dtGetMemberId = SqlHelper.ExecuteDataset(con, "IVRCustomerDetails_insert", 0, DBNull.Value, DBNull.Value, 0, 0, MobileNo, "A", MemberLoginID).Tables[0];
                     if (dtGetMemberId != null && dtGetMemberId.Rows.Count > 0)
                     {

                         MemberId = Convert.ToInt32(dtGetMemberId.Rows[0]["MemberId"]);


                     }
                     else
                     {
                         MemberId = 0;

                     }

                     if (MemberId == 0)
                     {
                         isold = false;
                     }
                     else
                     {
                         isold = true;
                     }
                     if (isold == true)
                     {
                         dtGetMemberComplaintNo = SqlHelper.ExecuteDataset(con, "IVRCustomerDetails_insert", MemberId, DBNull.Value, DBNull.Value, 0, 0, MobileNo, "F", MemberLoginID).Tables[0];
                         if (dtGetMemberComplaintNo != null && dtGetMemberComplaintNo.Rows.Count > 0)
                         {
                             System.Web.Script.Serialization.JavaScriptSerializer serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                             List<Dictionary<string, object>> rows = new List<Dictionary<string, object>>();
                             Dictionary<string, object> row;
                             foreach (DataRow dr in dtGetMemberComplaintNo.Rows)
                             {
                                 row = new Dictionary<string, object>();
                                 foreach (DataColumn col in dtGetMemberComplaintNo.Columns)
                                 {
                                     row.Add(col.ColumnName, dr[col]);
                                 }
                                 rows.Add(row);
                             }
                             

                             strReturnStatus = serializer.Serialize(rows);
                         }
                         else
                         {
                             Tickeno = "";
                         }
                     }
                 }
             }
             catch (Exception)
             {

                 throw;
             }
             finally
             {
                 con.Close();
                 con.Dispose();
             
             }
         }

        return strReturnStatus;
    }


}
