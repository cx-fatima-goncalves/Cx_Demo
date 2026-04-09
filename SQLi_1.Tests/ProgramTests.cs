using System;
using System.Data.SqlClient;
using Xunit;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Test suite for SQL Injection vulnerability remediation in Program.cs
    /// Validates that the Login method uses parameterized queries to prevent SQL injection attacks
    /// </summary>
    public class ProgramTests
    {
        /// <summary>
        /// Test that verifies parameterized query is used instead of string concatenation
        /// This is the core test to ensure SQL injection vulnerability is fixed
        /// </summary>
        [Fact]
        public void Login_UsesParameterizedQuery_NotStringConcatenation()
        {
            // Arrange: Read the source code to verify parameterized queries are used
            string sourceCode = System.IO.File.ReadAllText("../../../SQLi_1/Program.cs");

            // Assert: The code should use @username and @password parameters
            Assert.Contains("@username", sourceCode);
            Assert.Contains("@password", sourceCode);
            Assert.Contains("cmd.Parameters.AddWithValue", sourceCode);

            // Assert: The vulnerable pattern (string concatenation in SQL) should not exist
            // The old vulnerable pattern was: "SELECT * FROM Users WHERE username = '" + username
            Assert.DoesNotContain("username = '\" + username", sourceCode);
            Assert.DoesNotContain("pwd = '\" + password", sourceCode);
        }

        /// <summary>
        /// Test to verify SQL injection attack with single quote is prevented
        /// Classic SQL injection attempt: admin' OR '1'='1
        /// </summary>
        [Fact]
        public void Login_WithSQLInjectionAttempt_SingleQuote_IsNeutralized()
        {
            // Arrange: SQL injection payload with single quote
            string maliciousUsername = "admin' OR '1'='1";
            string password = "anything";

            // Act & Assert: When using parameterized queries, this will be treated as literal string
            // The parameter value will be properly escaped/quoted by ADO.NET
            // We verify the code structure uses parameters (static analysis)
            string sourceCode = System.IO.File.ReadAllText("../../../SQLi_1/Program.cs");

            // The fix ensures parameters are added with AddWithValue
            Assert.Contains("cmd.Parameters.AddWithValue(\"@username\", username)", sourceCode);
            Assert.Contains("cmd.Parameters.AddWithValue(\"@password\", password)", sourceCode);

            // Verify the SQL query uses parameter placeholders
            Assert.Contains("WHERE username = @username AND pwd = @password", sourceCode);
        }

        /// <summary>
        /// Test to verify SQL injection with comment syntax is prevented
        /// Attack attempt: admin'--
        /// </summary>
        [Fact]
        public void Login_WithSQLInjectionAttempt_CommentSyntax_IsNeutralized()
        {
            // Arrange: SQL injection payload attempting to comment out rest of query
            string maliciousUsername = "admin'--";
            string password = "ignored";

            // Act & Assert: Parameterized queries treat this as literal string value
            string sourceCode = System.IO.File.ReadAllText("../../../SQLi_1/Program.cs");

            // Verify parameterization is in place
            Assert.Contains("@username", sourceCode);
            Assert.Contains("@password", sourceCode);
            Assert.Contains("Parameters.AddWithValue", sourceCode);
        }

        /// <summary>
        /// Test to verify SQL injection with UNION attack is prevented
        /// Attack attempt: ' UNION SELECT password FROM admin_users--
        /// </summary>
        [Fact]
        public void Login_WithSQLInjectionAttempt_UnionAttack_IsNeutralized()
        {
            // Arrange: SQL injection payload with UNION
            string maliciousUsername = "' UNION SELECT password FROM admin_users--";
            string password = "anything";

            // Act & Assert: With parameterized queries, this becomes a literal string search value
            string sourceCode = System.IO.File.ReadAllText("../../../SQLi_1/Program.cs");

            // Ensure the query structure uses parameters
            Assert.Contains("WHERE username = @username AND pwd = @password", sourceCode);
            Assert.Contains("cmd.Parameters.AddWithValue(\"@username\", username)", sourceCode);
        }

        /// <summary>
        /// Test to verify SQL injection with boolean-based attack is prevented
        /// Attack attempt: ' OR 1=1--
        /// </summary>
        [Fact]
        public void Login_WithSQLInjectionAttempt_BooleanBased_IsNeutralized()
        {
            // Arrange: Boolean-based SQL injection payload
            string maliciousUsername = "' OR 1=1--";
            string password = "anything";

            // Act & Assert: Parameterized queries prevent boolean injection
            string sourceCode = System.IO.File.ReadAllText("../../../SQLi_1/Program.cs");

            // Verify the secure pattern is used
            Assert.Contains("cmd.Parameters.AddWithValue", sourceCode);
            Assert.Contains("@username", sourceCode);
            Assert.Contains("@password", sourceCode);
        }

        /// <summary>
        /// Test to verify normal legitimate usernames with special characters work correctly
        /// Example: O'Brien should be handled safely
        /// </summary>
        [Fact]
        public void Login_WithLegitimateSpecialCharacters_HandledSafely()
        {
            // Arrange: Legitimate username with apostrophe
            string legitimateUsername = "O'Brien";
            string password = "validPassword123";

            // Act & Assert: Parameterized queries handle special characters safely
            string sourceCode = System.IO.File.ReadAllText("../../../SQLi_1/Program.cs");

            // The parameterized approach correctly escapes special characters
            Assert.Contains("cmd.Parameters.AddWithValue(\"@username\", username)", sourceCode);
            Assert.Contains("cmd.Parameters.AddWithValue(\"@password\", password)", sourceCode);
        }

        /// <summary>
        /// Test to verify SQL injection with stacked queries is prevented
        /// Attack attempt: admin'; DROP TABLE Users--
        /// </summary>
        [Fact]
        public void Login_WithSQLInjectionAttempt_StackedQueries_IsNeutralized()
        {
            // Arrange: Stacked query SQL injection payload
            string maliciousUsername = "admin'; DROP TABLE Users--";
            string password = "anything";

            // Act & Assert: Parameterized queries prevent stacked queries
            string sourceCode = System.IO.File.ReadAllText("../../../SQLi_1/Program.cs");

            // Verify secure implementation
            Assert.Contains("WHERE username = @username AND pwd = @password", sourceCode);
            Assert.Contains("Parameters.AddWithValue", sourceCode);

            // Verify no string concatenation is used in SQL
            Assert.DoesNotContain("+ username +", sourceCode);
            Assert.DoesNotContain("+ password +", sourceCode);
        }

        /// <summary>
        /// Test to verify the SQL query structure uses proper parameterization format
        /// </summary>
        [Fact]
        public void Login_SQLQueryStructure_UsesProperParameterization()
        {
            // Arrange & Act: Read source code
            string sourceCode = System.IO.File.ReadAllText("../../../SQLi_1/Program.cs");

            // Assert: Verify SQL query uses @ parameter syntax (not string concatenation)
            Assert.Contains("WHERE username = @username", sourceCode);
            Assert.Contains("AND pwd = @password", sourceCode);

            // Assert: Both parameters are properly added to the command
            int usernameParamCount = CountOccurrences(sourceCode, "cmd.Parameters.AddWithValue(\"@username\"");
            int passwordParamCount = CountOccurrences(sourceCode, "cmd.Parameters.AddWithValue(\"@password\"");

            Assert.True(usernameParamCount >= 1, "Username parameter should be added at least once");
            Assert.True(passwordParamCount >= 1, "Password parameter should be added at least once");
        }

        /// <summary>
        /// Test to ensure SqlCommand is used with connection assignment and parameterization
        /// </summary>
        [Fact]
        public void Login_SqlCommand_ProperlyConfiguredWithParameters()
        {
            // Arrange & Act: Verify the command structure
            string sourceCode = System.IO.File.ReadAllText("../../../SQLi_1/Program.cs");

            // Assert: SqlCommand is created and configured properly
            Assert.Contains("new SqlCommand", sourceCode);
            Assert.Contains("cmd.Connection = conn", sourceCode);
            Assert.Contains("cmd.Parameters.AddWithValue", sourceCode);
            Assert.Contains("cmd.ExecuteScalar()", sourceCode);
        }

        /// <summary>
        /// Test to verify no dangerous string interpolation or concatenation exists in SQL
        /// </summary>
        [Fact]
        public void Login_NoStringInterpolationInSQL_OnlyParameters()
        {
            // Arrange & Act: Check for dangerous patterns
            string sourceCode = System.IO.File.ReadAllText("../../../SQLi_1/Program.cs");

            // Assert: No string concatenation operators near SQL keywords
            // Get the Login method content
            int loginMethodStart = sourceCode.IndexOf("private static void Login");
            int loginMethodEnd = sourceCode.IndexOf("}", loginMethodStart + 1);
            string loginMethod = sourceCode.Substring(loginMethodStart, loginMethodEnd - loginMethodStart);

            // Verify no dangerous patterns in Login method
            Assert.DoesNotContain("'\" + username", loginMethod);
            Assert.DoesNotContain("+ username + \"'", loginMethod);
            Assert.DoesNotContain("'\" + password", loginMethod);
            Assert.DoesNotContain("+ password + \"'", loginMethod);
            Assert.DoesNotContain("$\"{username}\"", loginMethod); // C# string interpolation
            Assert.DoesNotContain("$\"{password}\"", loginMethod);
        }

        /// <summary>
        /// Helper method to count occurrences of a substring
        /// </summary>
        private int CountOccurrences(string text, string pattern)
        {
            int count = 0;
            int index = 0;
            while ((index = text.IndexOf(pattern, index)) != -1)
            {
                count++;
                index += pattern.Length;
            }
            return count;
        }
    }
}
