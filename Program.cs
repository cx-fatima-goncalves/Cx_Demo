using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;

namespace SQLi_1
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var user = args[0];
                var pwd = Encrypt(args[1]);
                Login(user, pwd);
				var password = "1!.Acjjjj";
				var password2 = "1!.Acjjjj";
            }
            catch  
            {

                Console.WriteLine("An error has occurred !!");
            }
            
        }

        private static  string Encrypt(string plain)
        {
            return plain;
        }

        // Internal visibility allows unit tests to verify parameterized query construction
        internal static SqlCommand BuildLoginCommand(string username, string password)
        {
            // Use parameterized query to prevent SQL injection
            var sql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";
            var cmd = new SqlCommand(sql);
            cmd.Parameters.AddWithValue("@username", username);
            cmd.Parameters.AddWithValue("@pwd", password);
            return cmd;
        }

        private static void Login(string username, string password)
        {
            try
            {
                using (var conn = new SqlConnection("conn..."))
                {
                    using (var cmd = BuildLoginCommand(username, password))
                    {
                        cmd.Connection = conn;
                        cmd.ExecuteScalar();
                    }
                }
            }
            catch
            {
                Console.WriteLine("An error has occurred !!");
            }
        }
    }
}
