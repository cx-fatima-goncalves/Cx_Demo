using System;
using System.Data.SqlClient;
using System.Linq;
using Xunit;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Security tests to verify SQL injection vulnerability has been properly remediated
    /// and that the login functionality uses parameterized queries.
    /// </summary>
    public class LoginSecurityTests
    {
        #region SQL Injection Prevention Tests

        /// <summary>
        /// Test 1: Verify that the SQL command uses parameterized query format
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_UsesParameterizedQuery()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            Assert.NotNull(cmd);
            Assert.NotNull(cmd.CommandText);
            // Verify the SQL uses parameter placeholders (@username, @password) instead of concatenation
            Assert.Contains("@username", cmd.CommandText);
            Assert.Contains("@password", cmd.CommandText);
            // Verify that actual values are NOT directly in the SQL string
            Assert.DoesNotContain(username, cmd.CommandText);
            Assert.DoesNotContain(password, cmd.CommandText);
        }

        /// <summary>
        /// Test 2: Verify that SQL command has exactly 2 parameters (username and password)
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_HasTwoParameters()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            Assert.NotNull(cmd.Parameters);
            Assert.Equal(2, cmd.Parameters.Count);
        }

        /// <summary>
        /// Test 3: Verify that username parameter is properly set
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_UsernameParameterIsProperlySet()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            var usernameParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@username");
            Assert.NotNull(usernameParam);
            Assert.Equal(username, usernameParam.Value);
        }

        /// <summary>
        /// Test 4: Verify that password parameter is properly set
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_PasswordParameterIsProperlySet()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            var passwordParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@password");
            Assert.NotNull(passwordParam);
            Assert.Equal(password, passwordParam.Value);
        }

        /// <summary>
        /// Test 5: SQL Injection Attack Vector 1 - Classic OR '1'='1' attack
        /// Verify that SQL injection payload in username is treated as a parameter value, not SQL code
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_PreventsSQLInjection_OrOneEqualsOne()
        {
            // Arrange - Classic SQL injection attempt
            string maliciousUsername = "admin' OR '1'='1";
            string password = "irrelevant";

            // Act
            var cmd = Program.CreateSecureLoginCommand(maliciousUsername, password);

            // Assert
            // The malicious string should be in the parameter value, NOT in the SQL command text
            var usernameParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@username");
            Assert.NotNull(usernameParam);
            Assert.Equal(maliciousUsername, usernameParam.Value);

            // Verify the SQL command text still only contains parameter placeholders
            Assert.Contains("@username", cmd.CommandText);
            Assert.DoesNotContain("OR '1'='1'", cmd.CommandText);
        }

        /// <summary>
        /// Test 6: SQL Injection Attack Vector 2 - Comment-based injection
        /// Verify that SQL comment characters are treated as literal data
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_PreventsSQLInjection_CommentInjection()
        {
            // Arrange - SQL injection using comment to bypass password check
            string maliciousUsername = "admin'--";
            string password = "irrelevant";

            // Act
            var cmd = Program.CreateSecureLoginCommand(maliciousUsername, password);

            // Assert
            var usernameParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@username");
            Assert.NotNull(usernameParam);
            Assert.Equal(maliciousUsername, usernameParam.Value);

            // Verify the SQL still checks both username AND password
            Assert.Contains("@username", cmd.CommandText);
            Assert.Contains("@password", cmd.CommandText);
            Assert.Contains("AND", cmd.CommandText.ToUpper());
        }

        /// <summary>
        /// Test 7: SQL Injection Attack Vector 3 - UNION-based injection
        /// Verify that UNION attack attempts are treated as parameter values
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_PreventsSQLInjection_UnionAttack()
        {
            // Arrange - UNION-based SQL injection attempt
            string maliciousUsername = "admin' UNION SELECT * FROM Users--";
            string password = "irrelevant";

            // Act
            var cmd = Program.CreateSecureLoginCommand(maliciousUsername, password);

            // Assert
            var usernameParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@username");
            Assert.NotNull(usernameParam);
            Assert.Equal(maliciousUsername, usernameParam.Value);

            // The command text should not contain UNION keyword
            Assert.DoesNotContain("UNION", cmd.CommandText.ToUpper());
        }

        /// <summary>
        /// Test 8: SQL Injection Attack Vector 4 - Stacked queries attack
        /// Verify that attempts to execute additional SQL statements are treated as parameter values
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_PreventsSQLInjection_StackedQueries()
        {
            // Arrange - Stacked queries SQL injection attempt
            string maliciousUsername = "admin'; DROP TABLE Users;--";
            string password = "irrelevant";

            // Act
            var cmd = Program.CreateSecureLoginCommand(maliciousUsername, password);

            // Assert
            var usernameParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@username");
            Assert.NotNull(usernameParam);
            Assert.Equal(maliciousUsername, usernameParam.Value);

            // The command text should not contain DROP or semicolon
            Assert.DoesNotContain("DROP", cmd.CommandText.ToUpper());
            Assert.DoesNotContain(";", cmd.CommandText);
        }

        /// <summary>
        /// Test 9: SQL Injection Attack Vector 5 - Blind SQL injection
        /// Verify that boolean-based blind SQL injection is treated as parameter value
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_PreventsSQLInjection_BlindInjection()
        {
            // Arrange - Blind SQL injection attempt
            string maliciousUsername = "admin' AND 1=1--";
            string password = "irrelevant";

            // Act
            var cmd = Program.CreateSecureLoginCommand(maliciousUsername, password);

            // Assert
            var usernameParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@username");
            Assert.NotNull(usernameParam);
            Assert.Equal(maliciousUsername, usernameParam.Value);

            // Verify parameter is used and not concatenated into SQL
            Assert.Contains("@username", cmd.CommandText);
        }

        /// <summary>
        /// Test 10: SQL Injection Attack Vector 6 - Password field injection
        /// Verify that password parameter is also safe from SQL injection
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_PreventsSQLInjection_PasswordField()
        {
            // Arrange - SQL injection via password field
            string username = "testuser";
            string maliciousPassword = "password' OR '1'='1";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, maliciousPassword);

            // Assert
            var passwordParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@password");
            Assert.NotNull(passwordParam);
            Assert.Equal(maliciousPassword, passwordParam.Value);

            // Verify the SQL command text doesn't contain the injection payload
            Assert.DoesNotContain("OR '1'='1'", cmd.CommandText);
        }

        #endregion

        #region Functional Tests

        /// <summary>
        /// Test 11: Verify command works with normal alphanumeric credentials
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_WorksWithNormalCredentials()
        {
            // Arrange
            string username = "john_doe";
            string password = "SecureP@ssw0rd";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            Assert.NotNull(cmd);
            Assert.NotNull(cmd.CommandText);
            Assert.Equal(2, cmd.Parameters.Count);
        }

        /// <summary>
        /// Test 12: Verify command handles empty strings safely
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_HandlesEmptyStrings()
        {
            // Arrange
            string username = "";
            string password = "";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            Assert.NotNull(cmd);
            var usernameParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@username");
            var passwordParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@password");
            Assert.NotNull(usernameParam);
            Assert.NotNull(passwordParam);
            Assert.Equal("", usernameParam.Value);
            Assert.Equal("", passwordParam.Value);
        }

        /// <summary>
        /// Test 13: Verify command handles special characters in legitimate credentials
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_HandlesSpecialCharacters()
        {
            // Arrange - Legitimate username/password with special characters
            string username = "user@email.com";
            string password = "P@ssw0rd!#$%";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            var usernameParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@username");
            var passwordParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@password");
            Assert.NotNull(usernameParam);
            Assert.NotNull(passwordParam);
            Assert.Equal(username, usernameParam.Value);
            Assert.Equal(password, passwordParam.Value);
        }

        /// <summary>
        /// Test 14: Verify command handles unicode characters
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_HandlesUnicodeCharacters()
        {
            // Arrange
            string username = "用户名";
            string password = "パスワード";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            var usernameParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@username");
            var passwordParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@password");
            Assert.NotNull(usernameParam);
            Assert.NotNull(passwordParam);
            Assert.Equal(username, usernameParam.Value);
            Assert.Equal(password, passwordParam.Value);
        }

        /// <summary>
        /// Test 15: Verify command handles very long input strings
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_HandlesLongStrings()
        {
            // Arrange
            string username = new string('a', 1000);
            string password = new string('b', 1000);

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            var usernameParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@username");
            var passwordParam = cmd.Parameters.Cast<SqlParameter>()
                .FirstOrDefault(p => p.ParameterName == "@password");
            Assert.NotNull(usernameParam);
            Assert.NotNull(passwordParam);
            Assert.Equal(username, usernameParam.Value);
            Assert.Equal(password, passwordParam.Value);
        }

        #endregion

        #region Regression Tests

        /// <summary>
        /// Test 16: Verify SQL command structure matches expected secure format
        /// This test will fail if someone reverts to string concatenation
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_DoesNotUseConcatenation()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            // The SQL should NOT contain concatenation operators or the actual values
            string sql = cmd.CommandText;
            Assert.DoesNotContain("+", sql);
            Assert.DoesNotContain(username, sql);
            Assert.DoesNotContain(password, sql);

            // Should contain parameter placeholders
            Assert.Contains("@username", sql);
            Assert.Contains("@password", sql);
        }

        /// <summary>
        /// Test 17: Verify all parameters are properly parameterized
        /// Ensures no parameters are null or missing
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_AllParametersAreProperlySet()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            Assert.All(cmd.Parameters.Cast<SqlParameter>(), param =>
            {
                Assert.NotNull(param.ParameterName);
                Assert.NotNull(param.Value);
                Assert.True(param.ParameterName.StartsWith("@"));
            });
        }

        /// <summary>
        /// Test 18: Verify SQL query structure is correct
        /// This ensures the basic SQL syntax is preserved
        /// </summary>
        [Fact]
        public void CreateSecureLoginCommand_HasCorrectSQLStructure()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            var cmd = Program.CreateSecureLoginCommand(username, password);

            // Assert
            string sql = cmd.CommandText.ToUpper();
            Assert.Contains("SELECT", sql);
            Assert.Contains("FROM", sql);
            Assert.Contains("USERS", sql);
            Assert.Contains("WHERE", sql);
            Assert.Contains("AND", sql);
        }

        #endregion
    }
}
