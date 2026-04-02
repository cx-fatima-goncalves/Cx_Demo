using System.Data.SqlClient;

namespace SQLi_1
{
    /// <summary>
    /// Default implementation of data access operations
    /// </summary>
    internal class SqlDataAccess : IDataAccess
    {
        public SqlCommand CreateCommand(string query, SqlConnection connection)
        {
            return new SqlCommand(query, connection);
        }

        public object ExecuteScalar(SqlCommand command)
        {
            return command.ExecuteScalar();
        }
    }
}
