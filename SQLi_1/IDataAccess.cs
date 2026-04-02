using System.Data.SqlClient;

namespace SQLi_1
{
    /// <summary>
    /// Interface for data access operations to enable testing
    /// </summary>
    internal interface IDataAccess
    {
        SqlCommand CreateCommand(string query, SqlConnection connection);
        object ExecuteScalar(SqlCommand command);
    }
}
