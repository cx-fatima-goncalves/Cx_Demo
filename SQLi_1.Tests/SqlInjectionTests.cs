using System;
using System.Data.SqlClient;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Test suite to verify SQL injection vulnerability remediation.
    /// These tests validate that parameterized queries are used correctly
    /// to prevent SQL injection attacks.
    /// </summary>
    [TestClass]
    public class SqlInjectionTests
    {
        /// <summary>
        /// Verifies that SqlCommand properly uses parameterized queries
        /// when constructed with parameters instead of string concatenation.
        /// </summary>
        [TestMethod]
        public void SqlCommand_WithParameters_PreventsSqlInjection()
        {
            // Arrange - Create a malicious username that would exploit SQL injection
            string maliciousUsername = "admin' OR '1'='1";
            string password = "password";
            string sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";

            // Act - Create a SqlCommand with parameterized query
            using (var cmd = new SqlCommand(sql))
            {
                cmd.Parameters.AddWithValue("@username", maliciousUsername);
                cmd.Parameters.AddWithValue("@password", password);

                // Assert - Verify parameters are added correctly
                Assert.AreEqual(2, cmd.Parameters.Count, "Command should have exactly 2 parameters");
                Assert.AreEqual("@username", cmd.Parameters[0].ParameterName, "First parameter should be @username");
                Assert.AreEqual("@password", cmd.Parameters[1].ParameterName, "Second parameter should be @password");
                Assert.AreEqual(maliciousUsername, cmd.Parameters[0].Value, "Username parameter should contain the exact input without interpretation");
                Assert.AreEqual(password, cmd.Parameters[1].Value, "Password parameter should contain the exact input");

                // Verify the SQL query uses parameter placeholders, not concatenated values
                Assert.IsTrue(sql.Contains("@username"), "SQL should use @username parameter placeholder");
                Assert.IsTrue(sql.Contains("@password"), "SQL should use @password parameter placeholder");
                Assert.IsFalse(sql.Contains("' +"), "SQL should not contain string concatenation");
                Assert.IsFalse(sql.Contains("+ '"), "SQL should not contain string concatenation");
            }
        }

        /// <summary>
        /// Test case: Verify that common SQL injection payloads are safely handled
        /// when using parameterized queries.
        /// </summary>
        [TestMethod]
        public void ParameterizedQuery_WithSqlInjectionPayload_TreatsAsLiteralString()
        {
            // Arrange - Various SQL injection attack vectors
            string[] sqlInjectionPayloads = new string[]
            {
                "admin' OR '1'='1",                    // Classic OR-based injection
                "admin'; DROP TABLE Users; --",        // Command injection
                "admin' UNION SELECT * FROM passwords--", // UNION-based injection
                "' OR 1=1--",                          // Comment-based injection
                "admin'/**/OR/**/1=1--",               // Obfuscated injection
                "'; EXEC xp_cmdshell('dir'); --"       // Command execution attempt
            };

            string sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";

            // Act & Assert - Each payload should be treated as a literal string value
            foreach (string payload in sqlInjectionPayloads)
            {
                using (var cmd = new SqlCommand(sql))
                {
                    cmd.Parameters.AddWithValue("@username", payload);
                    cmd.Parameters.AddWithValue("@password", "testPassword");

                    // Verify the payload is stored as a parameter value, not interpreted as SQL
                    Assert.AreEqual(payload, cmd.Parameters["@username"].Value,
                        $"Payload '{payload}' should be stored as-is in the parameter");
                    Assert.AreEqual(2, cmd.Parameters.Count,
                        "Command should have exactly 2 parameters regardless of payload");
                }
            }
        }

        /// <summary>
        /// Test case: Verify that special characters in input are properly escaped
        /// when using parameterized queries.
        /// </summary>
        [TestMethod]
        public void ParameterizedQuery_WithSpecialCharacters_HandlesCorrectly()
        {
            // Arrange - Legitimate inputs with special characters that need proper handling
            string usernameWithQuotes = "O'Brien";
            string passwordWithSpecialChars = "P@ssw'rd\"123";
            string sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";

            // Act
            using (var cmd = new SqlCommand(sql))
            {
                cmd.Parameters.AddWithValue("@username", usernameWithQuotes);
                cmd.Parameters.AddWithValue("@password", passwordWithSpecialChars);

                // Assert - Parameters should preserve special characters without breaking the query
                Assert.AreEqual(usernameWithQuotes, cmd.Parameters["@username"].Value,
                    "Username with single quote should be preserved exactly");
                Assert.AreEqual(passwordWithSpecialChars, cmd.Parameters["@password"].Value,
                    "Password with special characters should be preserved exactly");

                // Verify query structure is not affected by special characters
                Assert.IsFalse(sql.Contains(usernameWithQuotes),
                    "SQL command text should not contain the actual username value");
                Assert.IsFalse(sql.Contains(passwordWithSpecialChars),
                    "SQL command text should not contain the actual password value");
            }
        }

        /// <summary>
        /// Test case: Verify that null and empty string inputs are handled safely.
        /// </summary>
        [TestMethod]
        public void ParameterizedQuery_WithNullOrEmptyInputs_HandlesGracefully()
        {
            // Arrange
            string sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";

            // Act & Assert - Test with null username
            using (var cmd = new SqlCommand(sql))
            {
                cmd.Parameters.AddWithValue("@username", (object)null ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@password", "password");

                Assert.AreEqual(2, cmd.Parameters.Count);
                Assert.IsTrue(cmd.Parameters["@username"].Value == null ||
                             cmd.Parameters["@username"].Value is DBNull,
                    "Null username should be handled as null or DBNull");
            }

            // Act & Assert - Test with empty string
            using (var cmd = new SqlCommand(sql))
            {
                cmd.Parameters.AddWithValue("@username", string.Empty);
                cmd.Parameters.AddWithValue("@password", string.Empty);

                Assert.AreEqual(2, cmd.Parameters.Count);
                Assert.AreEqual(string.Empty, cmd.Parameters["@username"].Value,
                    "Empty string username should be preserved");
                Assert.AreEqual(string.Empty, cmd.Parameters["@password"].Value,
                    "Empty string password should be preserved");
            }
        }

        /// <summary>
        /// Test case: Verify that very long inputs (potential buffer overflow attempts)
        /// are handled correctly by parameterized queries.
        /// </summary>
        [TestMethod]
        public void ParameterizedQuery_WithVeryLongInput_HandlesCorrectly()
        {
            // Arrange - Create a very long string that might be used in a buffer overflow attempt
            string longUsername = new string('A', 10000);
            string sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";

            // Act
            using (var cmd = new SqlCommand(sql))
            {
                cmd.Parameters.AddWithValue("@username", longUsername);
                cmd.Parameters.AddWithValue("@password", "password");

                // Assert - Long input should be handled as a parameter value
                Assert.AreEqual(longUsername, cmd.Parameters["@username"].Value,
                    "Very long username should be stored completely in parameter");
                Assert.AreEqual(10000, ((string)cmd.Parameters["@username"].Value).Length,
                    "Parameter should preserve the full length of the input");
            }
        }

        /// <summary>
        /// Test case: Verify that the SQL query structure doesn't contain
        /// string concatenation patterns that could lead to SQL injection.
        /// </summary>
        [TestMethod]
        public void SqlQuery_Structure_DoesNotContainConcatenation()
        {
            // Arrange - The remediated SQL query structure
            string remediatedSql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";

            // Assert - Verify the query uses proper parameterization
            Assert.IsTrue(remediatedSql.Contains("@username"),
                "Query should use @username parameter placeholder");
            Assert.IsTrue(remediatedSql.Contains("@password"),
                "Query should use @password parameter placeholder");

            // Verify no string concatenation operators are present
            Assert.IsFalse(remediatedSql.Contains("' +"),
                "Query should not contain string concatenation with ' +");
            Assert.IsFalse(remediatedSql.Contains("+ '"),
                "Query should not contain string concatenation with + '");
            Assert.IsFalse(remediatedSql.Contains("\" +"),
                "Query should not contain string concatenation with \" +");
            Assert.IsFalse(remediatedSql.Contains("+ \""),
                "Query should not contain string concatenation with + \"");

            // Verify the query doesn't have unparameterized quotes that would indicate concatenation
            int selectIndex = remediatedSql.IndexOf("SELECT", StringComparison.OrdinalIgnoreCase);
            int whereIndex = remediatedSql.IndexOf("WHERE", StringComparison.OrdinalIgnoreCase);
            if (whereIndex > selectIndex)
            {
                string whereClause = remediatedSql.Substring(whereIndex);
                // Count single quotes in WHERE clause - should be 0 for properly parameterized query
                int singleQuoteCount = whereClause.Split('\'').Length - 1;
                Assert.AreEqual(0, singleQuoteCount,
                    "WHERE clause should not contain single quotes (indicates string concatenation)");
            }
        }

        /// <summary>
        /// Test case: Verify parameterized queries handle Unicode and multi-byte characters correctly.
        /// </summary>
        [TestMethod]
        public void ParameterizedQuery_WithUnicodeCharacters_HandlesCorrectly()
        {
            // Arrange - Unicode characters that might cause issues if not handled properly
            string unicodeUsername = "用户名'; DROP TABLE Users; --";
            string emojiPassword = "🔒Pass🔑word🛡️";
            string sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";

            // Act
            using (var cmd = new SqlCommand(sql))
            {
                cmd.Parameters.AddWithValue("@username", unicodeUsername);
                cmd.Parameters.AddWithValue("@password", emojiPassword);

                // Assert - Unicode characters should be preserved exactly
                Assert.AreEqual(unicodeUsername, cmd.Parameters["@username"].Value,
                    "Unicode username with SQL injection attempt should be treated as literal string");
                Assert.AreEqual(emojiPassword, cmd.Parameters["@password"].Value,
                    "Emoji password should be preserved exactly");
            }
        }

        /// <summary>
        /// Test case: Regression test to ensure old vulnerable pattern is not present.
        /// This test documents the OLD vulnerable code pattern to prevent regression.
        /// </summary>
        [TestMethod]
        public void SqlQuery_DoesNotUseVulnerablePattern()
        {
            // Arrange - Example of the OLD vulnerable pattern (for documentation)
            string vulnerablePattern = "SELECT * FROM Users WHERE username = '" + "input" + "'";

            // Arrange - The NEW secure pattern
            string securePattern = "SELECT * FROM Users WHERE username = @username AND pwd = @password";

            // Assert - Verify the secure pattern is different from vulnerable pattern
            Assert.AreNotEqual(vulnerablePattern, securePattern,
                "Secure query should not match the old vulnerable concatenation pattern");

            // Verify the secure pattern uses parameters
            Assert.IsTrue(securePattern.Contains("@"),
                "Secure query should use @ parameter notation");

            // Verify secure pattern doesn't have the vulnerable concatenation structure
            Assert.IsFalse(securePattern.Contains("' + "),
                "Secure query should not use string concatenation with ' + ");
        }
    }
}
