using System;
using System.Data;
using System.Data.SqlClient;
using NUnit.Framework;
using SQLi_1;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Security tests to verify SQL injection vulnerability has been properly remediated
    /// Tests validate that parameterized queries are used and malicious input is handled safely
    /// </summary>
    [TestFixture]
    public class LoginSecurityTests
    {
        /// <summary>
        /// Mock data access implementation for testing
        /// Captures SQL commands to verify parameterization
        /// </summary>
        private class MockDataAccess : IDataAccess
        {
            public SqlCommand CapturedCommand { get; private set; }
            public string CapturedQuery { get; private set; }
            public int ParameterCount { get; private set; }
            public bool HasUsernameParameter { get; private set; }
            public bool HasPasswordParameter { get; private set; }
            public object UsernameValue { get; private set; }
            public object PasswordValue { get; private set; }

            public SqlCommand CreateCommand(string query, SqlConnection connection)
            {
                CapturedQuery = query;
                var cmd = new SqlCommand(query, connection);
                CapturedCommand = cmd;
                return cmd;
            }

            public object ExecuteScalar(SqlCommand command)
            {
                // Capture parameters before execution
                ParameterCount = command.Parameters.Count;
                HasUsernameParameter = command.Parameters.Contains("@username");
                HasPasswordParameter = command.Parameters.Contains("@password");

                if (HasUsernameParameter)
                {
                    UsernameValue = command.Parameters["@username"].Value;
                }
                if (HasPasswordParameter)
                {
                    PasswordValue = command.Parameters["@password"].Value;
                }

                // Don't actually execute - just return null
                return null;
            }
        }

        [Test]
        [Description("Test that the Login method uses parameterized queries, not string concatenation")]
        public void Login_UsesParameterizedQuery_NotStringConcatenation()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            var username = "testuser";
            var password = "testpass";

            // Act
            Program.Login(username, password, mockDataAccess);

            // Assert - Query should contain parameter placeholders, not actual values
            Assert.That(mockDataAccess.CapturedQuery, Does.Contain("@username"),
                "Query should use @username parameter placeholder");
            Assert.That(mockDataAccess.CapturedQuery, Does.Contain("@password"),
                "Query should use @password parameter placeholder");
            Assert.That(mockDataAccess.CapturedQuery, Does.Not.Contain(username),
                "Query should NOT contain the actual username value - it should be parameterized");
            Assert.That(mockDataAccess.CapturedQuery, Does.Not.Contain(password),
                "Query should NOT contain the actual password value - it should be parameterized");
        }

        [Test]
        [Description("Test that SQL injection attack with OR clause is prevented")]
        public void Login_WithSQLInjectionORClause_IsParameterized()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            // Classic SQL injection attempt: ' OR '1'='1
            var maliciousUsername = "admin' OR '1'='1";
            var password = "password";

            // Act
            Program.Login(maliciousUsername, password, mockDataAccess);

            // Assert - The malicious input should be treated as a literal string parameter value
            Assert.That(mockDataAccess.HasUsernameParameter, Is.True,
                "Username should be passed as a parameter");
            Assert.That(mockDataAccess.UsernameValue, Is.EqualTo(maliciousUsername),
                "The malicious input should be treated as a literal string value, not executed as SQL");
            Assert.That(mockDataAccess.ParameterCount, Is.EqualTo(2),
                "Should have exactly 2 parameters (username and password)");
        }

        [Test]
        [Description("Test that SQL injection with UNION SELECT attack is prevented")]
        public void Login_WithSQLInjectionUNION_IsParameterized()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            // UNION-based SQL injection attempt
            var maliciousUsername = "admin' UNION SELECT * FROM Users--";
            var password = "password";

            // Act
            Program.Login(maliciousUsername, password, mockDataAccess);

            // Assert
            Assert.That(mockDataAccess.HasUsernameParameter, Is.True,
                "Username should be passed as a parameter");
            Assert.That(mockDataAccess.UsernameValue, Is.EqualTo(maliciousUsername),
                "UNION injection attempt should be treated as literal string");
            Assert.That(mockDataAccess.CapturedQuery, Does.Not.Contain("UNION"),
                "The query structure should not be modified by user input");
        }

        [Test]
        [Description("Test that SQL injection with comment syntax is prevented")]
        public void Login_WithSQLInjectionComment_IsParameterized()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            // SQL comment injection attempt: admin'--
            var maliciousUsername = "admin'--";
            var password = "ignoredpassword";

            // Act
            Program.Login(maliciousUsername, password, mockDataAccess);

            // Assert
            Assert.That(mockDataAccess.HasUsernameParameter, Is.True,
                "Username should be passed as a parameter");
            Assert.That(mockDataAccess.UsernameValue, Is.EqualTo(maliciousUsername),
                "Comment injection should be treated as literal string");
            Assert.That(mockDataAccess.HasPasswordParameter, Is.True,
                "Password parameter should still be present (not commented out)");
        }

        [Test]
        [Description("Test that both username and password parameters are properly set")]
        public void Login_SetsBothParameters_Correctly()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            var username = "validuser";
            var password = "validpass123";

            // Act
            Program.Login(username, password, mockDataAccess);

            // Assert
            Assert.That(mockDataAccess.ParameterCount, Is.EqualTo(2),
                "Should have exactly 2 parameters");
            Assert.That(mockDataAccess.HasUsernameParameter, Is.True,
                "Should have @username parameter");
            Assert.That(mockDataAccess.HasPasswordParameter, Is.True,
                "Should have @password parameter");
            Assert.That(mockDataAccess.UsernameValue, Is.EqualTo(username),
                "Username parameter should have correct value");
            Assert.That(mockDataAccess.PasswordValue, Is.EqualTo(password),
                "Password parameter should have correct value");
        }

        [Test]
        [Description("Test with special characters that are not SQL injection but valid input")]
        public void Login_WithSpecialCharactersInUsername_IsParameterized()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            // Username with special characters that should be allowed
            var username = "user@example.com";
            var password = "p@ssw0rd!";

            // Act
            Program.Login(username, password, mockDataAccess);

            // Assert
            Assert.That(mockDataAccess.UsernameValue, Is.EqualTo(username),
                "Special characters in username should be preserved");
            Assert.That(mockDataAccess.PasswordValue, Is.EqualTo(password),
                "Special characters in password should be preserved");
        }

        [Test]
        [Description("Test SQL injection with DROP TABLE command is prevented")]
        public void Login_WithDropTableInjection_IsParameterized()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            // Destructive SQL injection attempt
            var maliciousUsername = "admin'; DROP TABLE Users;--";
            var password = "password";

            // Act
            Program.Login(maliciousUsername, password, mockDataAccess);

            // Assert
            Assert.That(mockDataAccess.UsernameValue, Is.EqualTo(maliciousUsername),
                "DROP TABLE injection should be treated as literal string");
            Assert.That(mockDataAccess.CapturedQuery, Does.Not.Contain("DROP"),
                "Query should not contain DROP keyword from user input");
        }

        [Test]
        [Description("Test SQL injection with stacked queries is prevented")]
        public void Login_WithStackedQueriesInjection_IsParameterized()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            // Stacked query injection attempt
            var maliciousUsername = "admin'; INSERT INTO Users VALUES ('hacker','pass');--";
            var password = "password";

            // Act
            Program.Login(maliciousUsername, password, mockDataAccess);

            // Assert
            Assert.That(mockDataAccess.UsernameValue, Is.EqualTo(maliciousUsername),
                "Stacked query injection should be treated as literal string");
            Assert.That(mockDataAccess.CapturedQuery, Does.Not.Contain("INSERT"),
                "Query should not contain INSERT keyword from user input");
        }

        [Test]
        [Description("Test that empty strings are handled correctly")]
        public void Login_WithEmptyStrings_IsParameterized()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            var username = "";
            var password = "";

            // Act
            Program.Login(username, password, mockDataAccess);

            // Assert
            Assert.That(mockDataAccess.HasUsernameParameter, Is.True,
                "Should have username parameter even if empty");
            Assert.That(mockDataAccess.HasPasswordParameter, Is.True,
                "Should have password parameter even if empty");
            Assert.That(mockDataAccess.UsernameValue, Is.EqualTo(username),
                "Empty username should be passed as parameter");
        }

        [Test]
        [Description("Test SQL injection with quote escaping attempt is prevented")]
        public void Login_WithQuoteEscapingAttempt_IsParameterized()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            // Attempt to escape quotes
            var maliciousUsername = "admin\\' OR \\'1\\'=\\'1";
            var password = "password";

            // Act
            Program.Login(maliciousUsername, password, mockDataAccess);

            // Assert
            Assert.That(mockDataAccess.UsernameValue, Is.EqualTo(maliciousUsername),
                "Quote escaping attempt should be treated as literal string");
            Assert.That(mockDataAccess.HasUsernameParameter, Is.True,
                "Username should be parameterized");
        }

        [Test]
        [Description("Regression test: Verify parameterized query structure is correct")]
        public void Login_QueryStructure_IsCorrect()
        {
            // Arrange
            var mockDataAccess = new MockDataAccess();
            var username = "testuser";
            var password = "testpass";

            // Act
            Program.Login(username, password, mockDataAccess);

            // Assert - Verify the basic query structure
            Assert.That(mockDataAccess.CapturedQuery, Does.Contain("SELECT"),
                "Query should be a SELECT statement");
            Assert.That(mockDataAccess.CapturedQuery, Does.Contain("FROM Users"),
                "Query should select from Users table");
            Assert.That(mockDataAccess.CapturedQuery, Does.Contain("WHERE"),
                "Query should have a WHERE clause");
            Assert.That(mockDataAccess.CapturedQuery, Does.Contain("username = @username"),
                "Query should compare username with @username parameter");
            Assert.That(mockDataAccess.CapturedQuery, Does.Contain("pwd = @password"),
                "Query should compare pwd with @password parameter");
        }
    }
}
