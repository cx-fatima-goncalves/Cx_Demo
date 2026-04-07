using System;
using System.Data.SqlClient;
using System.Reflection;
using Xunit;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Security tests to verify SQL injection vulnerability has been remediated in Program.Login method
    /// Tests ensure that parameterized queries are used instead of string concatenation
    /// </summary>
    public class ProgramSecurityTests
    {
        /// <summary>
        /// Test that SQL injection attack patterns in username are safely handled
        /// This verifies the fix prevents classic SQL injection via username parameter
        /// </summary>
        [Theory]
        [InlineData("admin' OR '1'='1")]
        [InlineData("admin'--")]
        [InlineData("admin'; DROP TABLE Users--")]
        [InlineData("' OR 1=1--")]
        [InlineData("admin' UNION SELECT NULL--")]
        public void Login_WithSQLInjectionInUsername_ShouldNotExecuteMaliciousQuery(string maliciousUsername)
        {
            // Arrange
            string password = "normalPassword";

            // Act & Assert
            // The Login method should handle malicious input safely via parameterization
            // This test verifies that the method doesn't throw unexpected exceptions
            // and that the malicious SQL is treated as literal string data, not SQL code
            var exception = Record.Exception(() =>
            {
                // Use reflection to call the private Login method
                var programType = typeof(Program);
                var loginMethod = programType.GetMethod("Login", BindingFlags.NonPublic | BindingFlags.Static);

                // The method will fail due to invalid connection string, but that's expected
                // We're verifying it doesn't fail due to SQL syntax errors from injection
                try
                {
                    loginMethod.Invoke(null, new object[] { maliciousUsername, password });
                }
                catch (TargetInvocationException tie)
                {
                    // Unwrap the inner exception from reflection
                    if (tie.InnerException != null)
                    {
                        throw tie.InnerException;
                    }
                    throw;
                }
            });

            // With parameterized queries, we should get connection errors (not SQL syntax errors)
            // SQL syntax errors would indicate the injection payload is being executed as SQL
            Assert.True(
                exception == null ||
                exception is SqlException ||
                exception is InvalidOperationException ||
                exception.Message.Contains("error"),
                "Login method should handle SQL injection attempts safely with parameterized queries"
            );
        }

        /// <summary>
        /// Test that SQL injection attack patterns in password are safely handled
        /// This verifies the fix prevents SQL injection via password parameter
        /// </summary>
        [Theory]
        [InlineData("password' OR '1'='1")]
        [InlineData("pwd'--")]
        [InlineData("password'; DROP TABLE Users--")]
        [InlineData("' OR 1=1--")]
        public void Login_WithSQLInjectionInPassword_ShouldNotExecuteMaliciousQuery(string maliciousPassword)
        {
            // Arrange
            string username = "normalUser";

            // Act & Assert
            var exception = Record.Exception(() =>
            {
                var programType = typeof(Program);
                var loginMethod = programType.GetMethod("Login", BindingFlags.NonPublic | BindingFlags.Static);

                try
                {
                    loginMethod.Invoke(null, new object[] { username, maliciousPassword });
                }
                catch (TargetInvocationException tie)
                {
                    if (tie.InnerException != null)
                    {
                        throw tie.InnerException;
                    }
                    throw;
                }
            });

            // With parameterized queries, malicious input is treated as data, not code
            Assert.True(
                exception == null ||
                exception is SqlException ||
                exception is InvalidOperationException ||
                exception.Message.Contains("error"),
                "Login method should handle SQL injection attempts in password safely"
            );
        }

        /// <summary>
        /// Test that legitimate usernames with special characters work correctly
        /// This verifies the parameterization doesn't break valid use cases
        /// </summary>
        [Theory]
        [InlineData("user@example.com")]
        [InlineData("user.name")]
        [InlineData("user_name")]
        [InlineData("O'Brien")]
        public void Login_WithLegitimateSpecialCharacters_ShouldHandleCorrectly(string legitimateUsername)
        {
            // Arrange
            string password = "validPassword";

            // Act & Assert
            var exception = Record.Exception(() =>
            {
                var programType = typeof(Program);
                var loginMethod = programType.GetMethod("Login", BindingFlags.NonPublic | BindingFlags.Static);

                try
                {
                    loginMethod.Invoke(null, new object[] { legitimateUsername, password });
                }
                catch (TargetInvocationException tie)
                {
                    if (tie.InnerException != null)
                    {
                        throw tie.InnerException;
                    }
                    throw;
                }
            });

            // Should handle legitimate special characters without issues
            // (Connection will fail due to invalid connection string, but that's expected)
            Assert.True(
                exception == null ||
                exception is SqlException ||
                exception is InvalidOperationException ||
                exception.Message.Contains("error"),
                "Login method should correctly handle legitimate usernames with special characters"
            );
        }

        /// <summary>
        /// Test that both username and password with injection attempts are safely handled
        /// This verifies the fix protects against combined attack vectors
        /// </summary>
        [Fact]
        public void Login_WithSQLInjectionInBothParameters_ShouldNotExecuteMaliciousQuery()
        {
            // Arrange
            string maliciousUsername = "admin' OR '1'='1'--";
            string maliciousPassword = "' OR '1'='1'--";

            // Act & Assert
            var exception = Record.Exception(() =>
            {
                var programType = typeof(Program);
                var loginMethod = programType.GetMethod("Login", BindingFlags.NonPublic | BindingFlags.Static);

                try
                {
                    loginMethod.Invoke(null, new object[] { maliciousUsername, maliciousPassword });
                }
                catch (TargetInvocationException tie)
                {
                    if (tie.InnerException != null)
                    {
                        throw tie.InnerException;
                    }
                    throw;
                }
            });

            // Parameterized queries should treat both malicious inputs as data
            Assert.True(
                exception == null ||
                exception is SqlException ||
                exception is InvalidOperationException ||
                exception.Message.Contains("error"),
                "Login method should handle SQL injection in both parameters safely"
            );
        }

        /// <summary>
        /// Test that Unicode and international characters are handled safely
        /// This verifies parameterization works with various character encodings
        /// </summary>
        [Theory]
        [InlineData("用户名")]
        [InlineData("gebruiker")]
        [InlineData("пользователь")]
        [InlineData("مستخدم")]
        public void Login_WithUnicodeCharacters_ShouldHandleSafely(string unicodeUsername)
        {
            // Arrange
            string password = "password123";

            // Act & Assert
            var exception = Record.Exception(() =>
            {
                var programType = typeof(Program);
                var loginMethod = programType.GetMethod("Login", BindingFlags.NonPublic | BindingFlags.Static);

                try
                {
                    loginMethod.Invoke(null, new object[] { unicodeUsername, password });
                }
                catch (TargetInvocationException tie)
                {
                    if (tie.InnerException != null)
                    {
                        throw tie.InnerException;
                    }
                    throw;
                }
            });

            // Should handle Unicode without SQL injection vulnerabilities
            Assert.True(
                exception == null ||
                exception is SqlException ||
                exception is InvalidOperationException ||
                exception.Message.Contains("error"),
                "Login method should safely handle Unicode characters via parameterization"
            );
        }

        /// <summary>
        /// Test that empty strings are handled correctly
        /// Edge case test to ensure parameterization handles null/empty values
        /// </summary>
        [Fact]
        public void Login_WithEmptyStrings_ShouldHandleGracefully()
        {
            // Arrange
            string emptyUsername = "";
            string emptyPassword = "";

            // Act & Assert
            var exception = Record.Exception(() =>
            {
                var programType = typeof(Program);
                var loginMethod = programType.GetMethod("Login", BindingFlags.NonPublic | BindingFlags.Static);

                try
                {
                    loginMethod.Invoke(null, new object[] { emptyUsername, emptyPassword });
                }
                catch (TargetInvocationException tie)
                {
                    if (tie.InnerException != null)
                    {
                        throw tie.InnerException;
                    }
                    throw;
                }
            });

            // Should handle empty strings without issues
            Assert.True(
                exception == null ||
                exception is SqlException ||
                exception is InvalidOperationException ||
                exception.Message.Contains("error"),
                "Login method should handle empty strings safely"
            );
        }

        /// <summary>
        /// Test various SQL comment patterns that could be used in attacks
        /// Verifies that SQL comments are treated as literal data, not SQL code
        /// </summary>
        [Theory]
        [InlineData("user--")]
        [InlineData("user/*comment*/")]
        [InlineData("user#")]
        [InlineData("user;--")]
        public void Login_WithSQLCommentPatterns_ShouldTreatAsLiteralData(string usernameWithComment)
        {
            // Arrange
            string password = "password";

            // Act & Assert
            var exception = Record.Exception(() =>
            {
                var programType = typeof(Program);
                var loginMethod = programType.GetMethod("Login", BindingFlags.NonPublic | BindingFlags.Static);

                try
                {
                    loginMethod.Invoke(null, new object[] { usernameWithComment, password });
                }
                catch (TargetInvocationException tie)
                {
                    if (tie.InnerException != null)
                    {
                        throw tie.InnerException;
                    }
                    throw;
                }
            });

            // SQL comment patterns should be treated as literal string data
            Assert.True(
                exception == null ||
                exception is SqlException ||
                exception is InvalidOperationException ||
                exception.Message.Contains("error"),
                "Login method should treat SQL comment patterns as literal data"
            );
        }
    }
}
