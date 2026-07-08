using System;
using System.Data.SqlClient;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SQLi_1
{
    /// <summary>
    /// Tests to verify that SQL injection vulnerability (CWE-89) is properly remediated
    /// in the Login flow by using parameterized queries instead of string concatenation.
    /// </summary>
    [TestClass]
    public class ProgramTests
    {
        // ----------------------------------------------------------------
        // Helper: build the SqlCommand via the same code path as production
        // ----------------------------------------------------------------

        private SqlCommand CreateLoginCommand(string username, string password)
        {
            return Program.BuildLoginCommand(username, password);
        }

        // ----------------------------------------------------------------
        // Parameterized query structure tests
        // ----------------------------------------------------------------

        [TestMethod]
        public void BuildLoginCommand_ReturnsParameterizedQuery_NotStringConcatenation()
        {
            // The command text must contain named parameters, not literal user values.
            var cmd = CreateLoginCommand("alice", "secret");

            Assert.IsTrue(
                cmd.CommandText.Contains("@username"),
                "CommandText must use @username parameter instead of inlining the value.");

            Assert.IsTrue(
                cmd.CommandText.Contains("@pwd"),
                "CommandText must use @pwd parameter instead of inlining the value.");
        }

        [TestMethod]
        public void BuildLoginCommand_CommandTextDoesNotContainLiteralUsername()
        {
            const string user = "alice";
            var cmd = CreateLoginCommand(user, "secret");

            Assert.IsFalse(
                cmd.CommandText.Contains(user),
                "CommandText must not contain the literal username value.");
        }

        [TestMethod]
        public void BuildLoginCommand_CommandTextDoesNotContainLiteralPassword()
        {
            const string pwd = "p@ssw0rd!";
            var cmd = CreateLoginCommand("alice", pwd);

            Assert.IsFalse(
                cmd.CommandText.Contains(pwd),
                "CommandText must not contain the literal password value.");
        }

        [TestMethod]
        public void BuildLoginCommand_HasTwoParameters()
        {
            var cmd = CreateLoginCommand("bob", "hunter2");

            Assert.AreEqual(2, cmd.Parameters.Count,
                "SqlCommand must have exactly two parameters (@username and @pwd).");
        }

        [TestMethod]
        public void BuildLoginCommand_UsernameParameterHasCorrectValue()
        {
            const string user = "charlie";
            var cmd = CreateLoginCommand(user, "pass");

            Assert.AreEqual(user, cmd.Parameters["@username"].Value,
                "@username parameter value must match the supplied username.");
        }

        [TestMethod]
        public void BuildLoginCommand_PasswordParameterHasCorrectValue()
        {
            const string pwd = "secureP@ss1";
            var cmd = CreateLoginCommand("dave", pwd);

            Assert.AreEqual(pwd, cmd.Parameters["@pwd"].Value,
                "@pwd parameter value must match the supplied password.");
        }

        // ----------------------------------------------------------------
        // SQL injection attack vector tests
        // ----------------------------------------------------------------

        [TestMethod]
        public void BuildLoginCommand_SqlInjectionPayloadInUsername_IsPassedAsParameter()
        {
            // A classic SQL injection payload that would bypass authentication
            // when concatenated directly into a query string.
            const string injectionPayload = "' OR '1'='1";
            var cmd = CreateLoginCommand(injectionPayload, "anything");

            // The payload must be stored as a bound parameter value, not embedded in SQL.
            Assert.IsFalse(
                cmd.CommandText.Contains("OR"),
                "Injection payload must not appear in CommandText.");

            Assert.AreEqual(injectionPayload, cmd.Parameters["@username"].Value,
                "Injection payload must be stored verbatim as a parameter value (not interpreted as SQL).");
        }

        [TestMethod]
        public void BuildLoginCommand_SqlInjectionPayloadInPassword_IsPassedAsParameter()
        {
            const string injectionPayload = "'; DROP TABLE Users; --";
            var cmd = CreateLoginCommand("alice", injectionPayload);

            Assert.IsFalse(
                cmd.CommandText.Contains("DROP"),
                "Injection payload must not appear in CommandText.");

            Assert.AreEqual(injectionPayload, cmd.Parameters["@pwd"].Value,
                "Injection payload must be stored verbatim as a parameter value.");
        }

        [TestMethod]
        public void BuildLoginCommand_TautologyInjection_IsPassedAsParameter()
        {
            // Tautology-based injection that would return all rows when concatenated.
            const string tautology = "admin'--";
            var cmd = CreateLoginCommand(tautology, "wrongpwd");

            Assert.IsFalse(
                cmd.CommandText.Contains("admin"),
                "Tautology payload must not appear in CommandText.");

            Assert.AreEqual(tautology, cmd.Parameters["@username"].Value);
        }

        [TestMethod]
        public void BuildLoginCommand_UnionBasedInjection_IsPassedAsParameter()
        {
            const string unionPayload = "' UNION SELECT null, null, null --";
            var cmd = CreateLoginCommand(unionPayload, "pass");

            Assert.IsFalse(
                cmd.CommandText.Contains("UNION"),
                "UNION-based injection must not appear in CommandText.");

            Assert.AreEqual(unionPayload, cmd.Parameters["@username"].Value);
        }

        [TestMethod]
        public void BuildLoginCommand_SpecialCharactersInCredentials_AreHandledSafely()
        {
            // Credentials that contain SQL-special characters must be treated as literals.
            const string username = "user'with\"quotes";
            const string password = "p@ss;word=with&special<chars>";
            var cmd = CreateLoginCommand(username, password);

            // Command text stays unchanged regardless of input content.
            Assert.AreEqual(
                "SELECT * FROM Users WHERE username = @username AND pwd = @pwd",
                cmd.CommandText,
                "CommandText must be a static parameterized template regardless of input.");

            Assert.AreEqual(username, cmd.Parameters["@username"].Value);
            Assert.AreEqual(password, cmd.Parameters["@pwd"].Value);
        }

        // ----------------------------------------------------------------
        // Query structure integrity tests
        // ----------------------------------------------------------------

        [TestMethod]
        public void BuildLoginCommand_CommandTextIsStaticTemplate()
        {
            // The SQL template must be identical regardless of what credentials are supplied.
            const string expectedSql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";

            var cmd1 = CreateLoginCommand("alice", "pwd1");
            var cmd2 = CreateLoginCommand("bob", "pwd2");
            var cmd3 = CreateLoginCommand("' OR 1=1 --", "' OR 1=1 --");

            Assert.AreEqual(expectedSql, cmd1.CommandText);
            Assert.AreEqual(expectedSql, cmd2.CommandText);
            Assert.AreEqual(expectedSql, cmd3.CommandText);
        }

        [TestMethod]
        public void BuildLoginCommand_EmptyUsername_IsHandledSafely()
        {
            var cmd = CreateLoginCommand(string.Empty, "password");

            Assert.AreEqual(string.Empty, cmd.Parameters["@username"].Value);
            Assert.IsFalse(cmd.CommandText.Contains("''"),
                "Empty string must be passed as a parameter, not inlined as an empty literal.");
        }

        [TestMethod]
        public void BuildLoginCommand_NullUsername_ThrowsOrHandlesGracefully()
        {
            // Passing null should either produce a DBNull parameter or throw ArgumentNullException —
            // it must NOT cause unhandled SQL string concatenation.
            try
            {
                var cmd = CreateLoginCommand(null, "password");
                // If no exception, verify null was converted to DBNull (safe parameterized null)
                var usernameValue = cmd.Parameters["@username"].Value;
                Assert.IsTrue(
                    usernameValue == null || usernameValue == DBNull.Value,
                    "Null input must be stored as null/DBNull, not inlined into the query.");
            }
            catch (ArgumentNullException)
            {
                // Also acceptable — explicit rejection of null input is safe.
            }
        }
    }
}
