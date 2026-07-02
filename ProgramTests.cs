using System;
using System.Data.SqlClient;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SQLi_1
{
    /// <summary>
    /// Tests verifying that the SQL injection vulnerability (CWE-89) in Login
    /// has been remediated by using parameterized queries.
    ///
    /// The original vulnerable code concatenated user-supplied values directly
    /// into the SQL string:
    ///   "SELECT * FROM Users WHERE username = '" + username + "' AND pwd = '" + password + "'"
    ///
    /// The fix replaces string concatenation with named SqlParameters (@username, @pwd),
    /// so the database driver treats the values as data, never as SQL syntax.
    /// </summary>
    [TestClass]
    public class ProgramTests
    {
        // -----------------------------------------------------------------------
        // Helper: build a command without a live connection (Connection = null).
        // We pass null because we only want to inspect CommandText and Parameters;
        // no query is actually executed.
        // -----------------------------------------------------------------------
        private static SqlCommand BuildCommand(string username, string password)
        {
            return Program.BuildLoginCommand(username, password, null);
        }

        // -----------------------------------------------------------------------
        // 1. The SQL string must NOT contain any user-supplied value literally.
        //    If the query text contains the username or password it means the
        //    vulnerable concatenation pattern is still in use.
        // -----------------------------------------------------------------------

        [TestMethod]
        public void BuildLoginCommand_CommandText_DoesNotContainUsername()
        {
            var username = "alice";
            var password = "secret";

            using (var cmd = BuildCommand(username, password))
            {
                StringAssert.DoesNotMatch(
                    cmd.CommandText,
                    new System.Text.RegularExpressions.Regex(System.Text.RegularExpressions.Regex.Escape(username)),
                    "CommandText must not embed the username literal — use a parameter instead.");
            }
        }

        [TestMethod]
        public void BuildLoginCommand_CommandText_DoesNotContainPassword()
        {
            var username = "alice";
            var password = "s3cr3t!";

            using (var cmd = BuildCommand(username, password))
            {
                StringAssert.DoesNotMatch(
                    cmd.CommandText,
                    new System.Text.RegularExpressions.Regex(System.Text.RegularExpressions.Regex.Escape(password)),
                    "CommandText must not embed the password literal — use a parameter instead.");
            }
        }

        // -----------------------------------------------------------------------
        // 2. SQL injection payloads must appear as parameter values, never as
        //    SQL syntax in CommandText.
        // -----------------------------------------------------------------------

        [TestMethod]
        public void BuildLoginCommand_ClassicInjectionPayload_IsContainedInParameter()
        {
            var injectionPayload = "' OR '1'='1";
            var password = "anything";

            using (var cmd = BuildCommand(injectionPayload, password))
            {
                // The query text must NOT contain the injection string
                Assert.IsFalse(
                    cmd.CommandText.Contains(injectionPayload),
                    "The injection payload must not appear in the SQL command text.");

                // The injection payload must be stored as a typed parameter value
                Assert.IsTrue(
                    cmd.Parameters.Contains("@username"),
                    "Parameter @username must exist.");

                Assert.AreEqual(
                    injectionPayload,
                    cmd.Parameters["@username"].Value,
                    "The injection payload is the parameter value — the DB driver will never execute it as SQL.");
            }
        }

        [TestMethod]
        public void BuildLoginCommand_UnionBasedInjection_DoesNotLeakIntoCommandText()
        {
            var payload = "admin' UNION SELECT * FROM sys.objects--";
            var password = "pass";

            using (var cmd = BuildCommand(payload, password))
            {
                Assert.IsFalse(
                    cmd.CommandText.Contains("UNION"),
                    "UNION keyword from user input must not appear in the SQL command text.");

                Assert.IsFalse(
                    cmd.CommandText.Contains("sys.objects"),
                    "Injection payload referencing system tables must not appear in the SQL command text.");
            }
        }

        [TestMethod]
        public void BuildLoginCommand_DropTableInjection_DoesNotLeakIntoCommandText()
        {
            var payload = "'; DROP TABLE Users;--";
            var password = "pass";

            using (var cmd = BuildCommand(payload, password))
            {
                Assert.IsFalse(
                    cmd.CommandText.Contains("DROP"),
                    "DROP statement from user input must not appear in the SQL command text.");
            }
        }

        // -----------------------------------------------------------------------
        // 3. Verify the command has exactly two parameters with the expected names.
        // -----------------------------------------------------------------------

        [TestMethod]
        public void BuildLoginCommand_HasExactlyTwoParameters()
        {
            using (var cmd = BuildCommand("user", "pass"))
            {
                Assert.AreEqual(2, cmd.Parameters.Count,
                    "The command must have exactly two parameters: @username and @pwd.");
            }
        }

        [TestMethod]
        public void BuildLoginCommand_HasUsernameParameter()
        {
            using (var cmd = BuildCommand("testuser", "testpass"))
            {
                Assert.IsTrue(cmd.Parameters.Contains("@username"),
                    "Parameter @username must be present.");
            }
        }

        [TestMethod]
        public void BuildLoginCommand_HasPasswordParameter()
        {
            using (var cmd = BuildCommand("testuser", "testpass"))
            {
                Assert.IsTrue(cmd.Parameters.Contains("@pwd"),
                    "Parameter @pwd must be present.");
            }
        }

        // -----------------------------------------------------------------------
        // 4. Parameter values must match the inputs exactly (no silent modification).
        // -----------------------------------------------------------------------

        [TestMethod]
        public void BuildLoginCommand_UsernameParameterValue_MatchesInput()
        {
            var username = "alice_smith";
            using (var cmd = BuildCommand(username, "pass"))
            {
                Assert.AreEqual(username, cmd.Parameters["@username"].Value,
                    "@username parameter value must equal the supplied username.");
            }
        }

        [TestMethod]
        public void BuildLoginCommand_PasswordParameterValue_MatchesInput()
        {
            var password = "P@ssw0rd!";
            using (var cmd = BuildCommand("user", password))
            {
                Assert.AreEqual(password, cmd.Parameters["@pwd"].Value,
                    "@pwd parameter value must equal the supplied password.");
            }
        }

        // -----------------------------------------------------------------------
        // 5. The fixed SQL query text must contain the named parameter placeholders.
        // -----------------------------------------------------------------------

        [TestMethod]
        public void BuildLoginCommand_CommandText_ContainsUsernameParameterPlaceholder()
        {
            using (var cmd = BuildCommand("user", "pass"))
            {
                StringAssert.Contains(cmd.CommandText, "@username",
                    "CommandText must reference the @username placeholder.");
            }
        }

        [TestMethod]
        public void BuildLoginCommand_CommandText_ContainsPwdParameterPlaceholder()
        {
            using (var cmd = BuildCommand("user", "pass"))
            {
                StringAssert.Contains(cmd.CommandText, "@pwd",
                    "CommandText must reference the @pwd placeholder.");
            }
        }

        // -----------------------------------------------------------------------
        // 6. Special characters in username/password must be handled safely
        //    without altering the SQL command text.
        // -----------------------------------------------------------------------

        [TestMethod]
        public void BuildLoginCommand_SpecialCharactersInUsername_CommandTextUnchanged()
        {
            var specialUser = "user'; SELECT 1--";
            var expectedSql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";

            using (var cmd = BuildCommand(specialUser, "pass"))
            {
                Assert.AreEqual(expectedSql, cmd.CommandText,
                    "CommandText must be identical regardless of special characters in input.");
            }
        }

        [TestMethod]
        public void BuildLoginCommand_NullByteInUsername_CommandTextUnchanged()
        {
            var nullByteUser = "admin\0";
            var expectedSql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";

            using (var cmd = BuildCommand(nullByteUser, "pass"))
            {
                Assert.AreEqual(expectedSql, cmd.CommandText,
                    "CommandText must be identical regardless of null bytes in input.");
            }
        }

        // -----------------------------------------------------------------------
        // 7. Regression: the original vulnerable pattern (string concatenation)
        //    must NOT be present in the command text.
        // -----------------------------------------------------------------------

        [TestMethod]
        public void BuildLoginCommand_CommandText_DoesNotUseSingleQuoteConcatenation()
        {
            // The old vulnerable pattern was:
            //   "SELECT * FROM Users WHERE username = '" + username + "' AND pwd = '" + password + "'"
            // After the fix, no single quotes around literal values should appear.
            using (var cmd = BuildCommand("alice", "pass"))
            {
                Assert.IsFalse(
                    cmd.CommandText.Contains("'"),
                    "CommandText must not contain single-quote delimiters that indicate unsafe string concatenation.");
            }
        }
    }
}
