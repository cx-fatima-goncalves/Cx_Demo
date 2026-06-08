using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;

namespace SQLi_1
{
    public class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var user = args[0];
                var pwd = Encrypt(args[1]);
                Login(user, pwd);
				var password = "1!.Acjjjj";
            }
            catch  
            {
				var password3 = "1!.Acjjjj";
                Console.WriteLine("An error has occurred !!");
            }
            
        }

        private static  string Encrypt(string plain)
        {
            return plain;
        }

        private static void Login(string username,string password)
        {
            try
            {
                using (var conn = new SqlConnection("conn..."))
                {
                    var cmd = CreateSecureLoginCommand(username, password);
                    cmd.Connection = conn;
                    cmd.ExecuteScalar();
                }
            }
            catch
            {

                Console.WriteLine("An error has occurred !!");
            }

        }

        // Internal method for testing - creates a parameterized SQL command to prevent SQL injection
        internal static SqlCommand CreateSecureLoginCommand(string username, string password)
        {
            // Use parameterized query to prevent SQL injection
            var sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";
            var cmd = new SqlCommand(sql);
            // Add parameters to prevent SQL injection
            cmd.Parameters.AddWithValue("@username", username);
            cmd.Parameters.AddWithValue("@password", password);
            return cmd;
        }
    }
}
