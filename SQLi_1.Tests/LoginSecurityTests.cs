using System;
using System.Data.SqlClient;
using Xunit;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Comprehensive test suite for SQL Injection vulnerability remediation.
    /// Tests verify that parameterized queries properly prevent SQL injection attacks.
    /// </summary>
    public class LoginSecurityTests
    {
        private const string TestConnectionString = "Data Source=(local);Initial Catalog=TestDB;Integrated Security=true";

        [Fact]
        public void CreateLoginCommand_WithNormalCredentials_UsesParameterizedQuery()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass123";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(username, password, connection);

                // Assert - Verify the SQL query uses parameterized placeholders
                Assert.Contains("@username", cmd.CommandText);
                Assert.Contains("@password", cmd.CommandText);

                // Assert - Verify no string concatenation (user input not in SQL text)
                Assert.DoesNotContain(username, cmd.CommandText);
                Assert.DoesNotContain(password, cmd.CommandText);

                // Assert - Verify parameters are properly added
                Assert.Equal(2, cmd.Parameters.Count);
                Assert.Equal(username, cmd.Parameters["@username"].Value);
                Assert.Equal(password, cmd.Parameters["@password"].Value);
            }
        }

        [Fact]
        public void CreateLoginCommand_WithSqlInjectionInUsername_ParametersSafelyEscaped()
        {
            // Arrange - Classic SQL injection attempt in username
            string maliciousUsername = "admin' OR '1'='1";
            string password = "anypassword";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(maliciousUsername, password, connection);

                // Assert - SQL injection payload should be treated as literal string parameter
                // The malicious input should NOT appear directly in the SQL command text
                Assert.DoesNotContain("OR '1'='1", cmd.CommandText);
                Assert.DoesNotContain("admin'", cmd.CommandText);

                // Assert - Malicious input is stored as a parameter value (safely escaped)
                Assert.Equal(maliciousUsername, cmd.Parameters["@username"].Value);

                // Assert - Query structure remains intact with parameterized placeholders
                Assert.Contains("@username", cmd.CommandText);
                Assert.Contains("@password", cmd.CommandText);
            }
        }

        [Fact]
        public void CreateLoginCommand_WithSqlInjectionInPassword_ParametersSafelyEscaped()
        {
            // Arrange - SQL injection attempt in password field
            string username = "testuser";
            string maliciousPassword = "' OR '1'='1' --";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(username, maliciousPassword, connection);

                // Assert - SQL injection payload treated as literal parameter value
                Assert.DoesNotContain("OR '1'='1'", cmd.CommandText);
                Assert.DoesNotContain("--", cmd.CommandText);

                // Assert - Malicious input stored safely as parameter
                Assert.Equal(maliciousPassword, cmd.Parameters["@password"].Value);

                // Assert - Parameterized query structure maintained
                Assert.Contains("@username", cmd.CommandText);
                Assert.Contains("@password", cmd.CommandText);
            }
        }

        [Fact]
        public void CreateLoginCommand_WithUnionBasedSqlInjection_ParametersSafelyEscaped()
        {
            // Arrange - UNION-based SQL injection attack
            string maliciousUsername = "admin' UNION SELECT * FROM users --";
            string password = "password";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(maliciousUsername, password, connection);

                // Assert - UNION attack payload does not alter query structure
                Assert.DoesNotContain("UNION SELECT", cmd.CommandText);

                // Assert - Attack payload treated as literal string value
                Assert.Equal(maliciousUsername, cmd.Parameters["@username"].Value);

                // Assert - Query maintains parameterized structure
                Assert.Equal(2, cmd.Parameters.Count);
            }
        }

        [Fact]
        public void CreateLoginCommand_WithCommentBasedSqlInjection_ParametersSafelyEscaped()
        {
            // Arrange - Comment-based SQL injection to bypass password check
            string maliciousUsername = "admin'--";
            string password = "irrelevant";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(maliciousUsername, password, connection);

                // Assert - SQL comment does not appear in command text
                Assert.DoesNotContain("'--", cmd.CommandText);

                // Assert - Both parameters are still present (not commented out)
                Assert.Equal(2, cmd.Parameters.Count);
                Assert.Contains("@password", cmd.CommandText);
            }
        }

        [Fact]
        public void CreateLoginCommand_WithTimingAttackPayload_ParametersSafelyEscaped()
        {
            // Arrange - Time-based blind SQL injection attempt
            string maliciousUsername = "admin' AND SLEEP(5) --";
            string password = "password";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(maliciousUsername, password, connection);

                // Assert - SLEEP function call not injected into query
                Assert.DoesNotContain("SLEEP", cmd.CommandText);
                Assert.DoesNotContain("AND SLEEP", cmd.CommandText);

                // Assert - Payload stored as safe parameter value
                Assert.Equal(maliciousUsername, cmd.Parameters["@username"].Value);
            }
        }

        [Fact]
        public void CreateLoginCommand_WithMultipleQuotes_ParametersSafelyEscaped()
        {
            // Arrange - Multiple quotes to break out of string context
            string maliciousUsername = "test''''''user";
            string password = "pass'''word";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(maliciousUsername, password, connection);

                // Assert - Multiple quotes in command text are only from SQL syntax
                // User input quotes should not appear in SQL text
                int quotesInCommandText = cmd.CommandText.Split('\'').Length - 1;
                int quotesInUsername = maliciousUsername.Split('\'').Length - 1;

                // Command text should not contain all the user's quotes
                Assert.True(quotesInCommandText < quotesInUsername);

                // Assert - Quotes stored safely in parameters
                Assert.Equal(maliciousUsername, cmd.Parameters["@username"].Value);
                Assert.Equal(password, cmd.Parameters["@password"].Value);
            }
        }

        [Fact]
        public void CreateLoginCommand_WithSpecialCharacters_ParametersSafelyEscaped()
        {
            // Arrange - Various special characters that could break SQL syntax
            string username = "user;DROP TABLE users;--";
            string password = "pass<script>alert('xss')</script>";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(username, password, connection);

                // Assert - DROP TABLE command not in query text
                Assert.DoesNotContain("DROP TABLE", cmd.CommandText);

                // Assert - Special characters handled as parameter values
                Assert.Equal(username, cmd.Parameters["@username"].Value);
                Assert.Equal(password, cmd.Parameters["@password"].Value);
            }
        }

        [Fact]
        public void CreateLoginCommand_WithEmptyStrings_HandlesGracefully()
        {
            // Arrange - Edge case with empty credentials
            string username = "";
            string password = "";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(username, password, connection);

                // Assert - Parameters created even for empty strings
                Assert.Equal(2, cmd.Parameters.Count);
                Assert.Equal(username, cmd.Parameters["@username"].Value);
                Assert.Equal(password, cmd.Parameters["@password"].Value);

                // Assert - Query structure intact
                Assert.Contains("@username", cmd.CommandText);
                Assert.Contains("@password", cmd.CommandText);
            }
        }

        [Fact]
        public void CreateLoginCommand_WithNullConnection_ThrowsArgumentNullException()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act & Assert - Should handle null connection appropriately
            Assert.Throws<ArgumentNullException>(() =>
            {
                Program.CreateLoginCommand(username, password, null);
            });
        }

        [Fact]
        public void CreateLoginCommand_WithVeryLongInput_ParametersSafelyEscaped()
        {
            // Arrange - Very long strings to test parameter handling
            string longUsername = new string('a', 1000) + "' OR '1'='1";
            string longPassword = new string('b', 1000);

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(longUsername, longPassword, connection);

                // Assert - Long input doesn't break parameterization
                Assert.Equal(2, cmd.Parameters.Count);
                Assert.Equal(longUsername, cmd.Parameters["@username"].Value);
                Assert.Equal(longPassword, cmd.Parameters["@password"].Value);

                // Assert - SQL injection in long string still blocked
                Assert.DoesNotContain("OR '1'='1'", cmd.CommandText);
            }
        }

        [Fact]
        public void CreateLoginCommand_VerifyQueryStructure_MatchesSecurePattern()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(username, password, connection);

                // Assert - Verify the exact secure query pattern
                string expectedPattern = "SELECT * FROM Users WHERE username = @username AND pwd = @password";
                Assert.Equal(expectedPattern, cmd.CommandText);

                // Assert - Verify no concatenation patterns in command text
                Assert.DoesNotContain("+", cmd.CommandText); // No string concatenation
                Assert.DoesNotContain("\"", cmd.CommandText); // No quote marks from concatenation
            }
        }

        [Fact]
        public void CreateLoginCommand_WithSemicolonInjection_ParametersSafelyEscaped()
        {
            // Arrange - Semicolon-based SQL injection to execute multiple statements
            string maliciousUsername = "admin'; DELETE FROM Users; --";
            string password = "password";

            // Act
            using (var connection = new SqlConnection(TestConnectionString))
            {
                var cmd = Program.CreateLoginCommand(maliciousUsername, password, connection);

                // Assert - DELETE statement not in command text
                Assert.DoesNotContain("DELETE FROM", cmd.CommandText);

                // Assert - Semicolons from user input not breaking query structure
                Assert.Equal(maliciousUsername, cmd.Parameters["@username"].Value);

                // Assert - Only one SQL statement in command
                // The command text should not have semicolons from user input
                Assert.DoesNotContain(";", cmd.CommandText);
            }
        }
    }
}
