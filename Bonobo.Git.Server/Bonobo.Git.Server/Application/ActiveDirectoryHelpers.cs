namespace Unosquare.AD.Application
{
    using System;
    using System.Collections.Generic;
    using System.DirectoryServices;
    using System.DirectoryServices.AccountManagement;
    using System.Globalization;
    using System.Security.Permissions;
    using System.Text;
    using Bonobo.Git.Server;

    public enum ActiveDirectoyGroupType
    {
        BuiltIn,
        Token,
        All,
    }

    /// <summary>
    /// Provides simple methods to perform common queries against an LDAP server
    /// </summary>
    public class ActiveDirectoryHelper
    {
        private const string LoginFilterFormatString = "(&(objectClass=person)(sAMAccountName={0}))";
        private const string PrincipalFilterFormatString = "(&(objectClass=person)(userPrincipalName={0}))";
        private const string GroupsFilterFormatString = "(&(objectClass=group))";
        private const string EmailSearchFilterFormatString = "(&(objectClass=person)(mail={0}))";
        private const string AllUsersFilterString = "(samAccountType=805306368)";

        public string LdapUsername { get; set; }
        public string LdapPassword { get; set; }
        public string LdapRootPath { get; set; }

        public ActiveDirectoryHelper()
        {
            this.LdapRootPath = UserConfigurationManager.LDAPPath;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ActiveDirectoryHelper"/> class.
        /// With specific path and credentials
        /// </summary>
        /// <param name="rootPath">The root path.</param>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        public ActiveDirectoryHelper(string rootPath, string username, string password)
        {
            this.LdapRootPath = rootPath;
            this.LdapUsername = username;
            this.LdapPassword = password;
        }

        /// <summary>
        /// Validates the user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        [DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
        public bool ValidateUser(string username, string password)
        {
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(LdapRootPath, username, password))
                {
                    object nativeObject = entry.NativeObject;
                    if (nativeObject == null) throw new KeyNotFoundException();
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Retrieve all DirectoryEntry objects with user details
        /// </summary>        
        /// <returns></returns>
        [DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
        public List<DirectoryEntry> GetAllUsers()
        {
            List<DirectoryEntry> entries = new List<DirectoryEntry>();
            using (var searcher = new DirectorySearcher(CreateEntry(), AllUsersFilterString, new string[] { "cn" }, SearchScope.Subtree))
            {
                var results = searcher.FindAll();
                if (results != null && results.Count > 0)
                {
                    foreach (SearchResult result in results)
                    {
                        entries.Add(GetEntryFromSearchResult(result));
                    }
                    return entries;
                }   
            }

            return null;
        }

        /// <summary>
        /// Finds the user by login.
        /// </summary>
        /// <param name="login">The login.</param>
        /// <returns></returns>
        [DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
        public DirectoryEntry FindUserByLogin(string login)
        {
            try
            {
                var queryFilter = string.Format(CultureInfo.InvariantCulture, LoginFilterFormatString, login);
                using (var searcher = new DirectorySearcher(CreateEntry(), queryFilter, new string[] { "cn" }, SearchScope.Subtree))
                {
                    var result = searcher.FindOne();
                    if (result != null) return GetEntryFromSearchResult(result);
                }
            } catch {}

            return null;

        }

        /// <summary>
        /// Finds the user by email.
        /// </summary>
        /// <param name="principalName">The email.</param>
        /// <returns></returns>
        [DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
        public DirectoryEntry FindUserByPrincipalName(string principalName)
        {
            var queryFilter = string.Format(CultureInfo.InvariantCulture, PrincipalFilterFormatString, principalName);
            using (var searcher = new DirectorySearcher(CreateEntry(), queryFilter, new string[] { "cn" }, SearchScope.Subtree))
            {
                var result = searcher.FindOne();
                if (result != null) return GetEntryFromSearchResult(result);
            }

            return null;
        }

        /// <summary>
        /// Gets the user group membership.
        /// </summary>
        /// <param name="userEntry">The user entry.</param>
        /// <returns></returns>
        [DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
        public string[] GetUserGroupMembership(DirectoryEntry userEntry, ActiveDirectoyGroupType types = ActiveDirectoyGroupType.All)
        {
            if (userEntry == null) throw new ArgumentNullException("userEntry");

            var userGroups = new List<string>();
            userEntry.RefreshCache(new string[] { "mail", "memberOf", "tokenGroups" });

            if (types == ActiveDirectoyGroupType.All || types == ActiveDirectoyGroupType.Token)
            {
                var tokenGroups = userEntry.Properties["tokenGroups"] as PropertyValueCollection;
                foreach (byte[] tokenGroup in tokenGroups)
                {

                    var sidPath = string.Format(CultureInfo.InvariantCulture, "/<SID={0}>", ToOctetString(tokenGroup));
                    var tokenGroupEntry = CreateEntry(sidPath);
                    var forceBindObj = tokenGroupEntry.NativeObject;
                    if (forceBindObj == null) throw new KeyNotFoundException();
                    userGroups.Add(tokenGroupEntry.Properties["name"].Value.ToString());
                }
            }

            if (types == ActiveDirectoyGroupType.All || types == ActiveDirectoyGroupType.BuiltIn)
            {
                var simpleGroups = userEntry.Properties["memberOf"] as PropertyValueCollection;
                foreach (string simpleGroup in simpleGroups)
                {
                    var groupEntry = CreateEntry("/" + simpleGroup);
                    var forceBindObj = groupEntry.NativeObject;
                    userGroups.Add(groupEntry.Properties["name"].Value.ToString());
                }
            }

            return userGroups.ToArray();
        }

        /// <summary>
        /// Enumerates the groups.
        /// </summary>
        /// <returns></returns>
        [DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
        public string[] EnumerateGroups()
        {
            var groupNames = new List<string>();
            var queryFilter = GroupsFilterFormatString;
            using (var searcher = new DirectorySearcher(CreateEntry(), queryFilter, new string[] { "cn" }, SearchScope.Subtree))
            {
                var results = searcher.FindAll();
                foreach (SearchResult result in results)
                {
                    groupNames.Add(result.Properties["cn"][0].ToString());
                }
            }

            return groupNames.ToArray();
        }

        /// <summary>
        /// Gets the entry from search result.
        /// </summary>
        /// <param name="result">The result.</param>
        /// <returns></returns>
        [DirectoryServicesPermission(SecurityAction.LinkDemand, Unrestricted = true)]
        private DirectoryEntry GetEntryFromSearchResult(SearchResult result)
        {
            if (string.IsNullOrWhiteSpace(LdapUsername) || string.IsNullOrWhiteSpace(LdapPassword))
            {
                return new DirectoryEntry(result.Path);
            }
            else
            {
                return new DirectoryEntry(result.Path, LdapUsername, LdapPassword);
            }
        }

        /// <summary>
        /// Creates the entry.
        /// </summary>
        /// <param name="subPath">The sub path.</param>
        /// <returns></returns>
        private DirectoryEntry CreateEntry(string subPath = null)
        {
            if (string.IsNullOrWhiteSpace(subPath))
                subPath = string.Empty;

            var path = (LdapRootPath + subPath);
            if (string.IsNullOrWhiteSpace(LdapUsername) || string.IsNullOrWhiteSpace(LdapPassword))
            {
                return new DirectoryEntry(path);
            }
            else
            {
                return new DirectoryEntry(path, LdapUsername, LdapPassword);
            }
        }

        /// <summary>
        /// Converts a byte array into an octed string for SID binding
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <returns></returns>
        static private string ToOctetString(byte[] bytes)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString("X2", CultureInfo.InvariantCulture));
            }

            return sb.ToString();
        }

    }
}