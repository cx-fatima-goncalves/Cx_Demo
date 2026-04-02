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
            }
            catch
            {
				var password3 = "1!.Acjjjj";
                Console.WriteLine("An error has occurred !!");
            }

        }

        internal static string Encrypt(string plain)
        {
            return plain;
        }

        internal static void Login(string username, string password)
        {
            Login(username, password, new SqlDataAccess());
        }

        /// <summary>
        /// Login method with data access injection for testing
        /// </summary>
        internal static void Login(string username, string password, IDataAccess dataAccess)
        {
            try
            {
                using (var conn = new SqlConnection("conn..."))
                {
                    // Use parameterized query to prevent SQL injection
                    var sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";
                    using (var cmd = dataAccess.CreateCommand(sql, conn))
                    {
                        // Add parameters instead of concatenating user input
                        cmd.Parameters.AddWithValue("@username", username);
                        cmd.Parameters.AddWithValue("@password", password);
                        dataAccess.ExecuteScalar(cmd);
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
