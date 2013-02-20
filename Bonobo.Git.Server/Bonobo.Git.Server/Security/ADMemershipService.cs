using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using Bonobo.Git.Server.Data;
using System.Data;
using Bonobo.Git.Server.Models;
using Unosquare.AD.Application;
using System.DirectoryServices;

namespace Bonobo.Git.Server.Security
{
    public class ADMemershipService : IMembershipService
    {
        public bool ValidateUser(string username, string password)
        {
            using (var database = new DataEntities())
            {
                if (String.IsNullOrEmpty(username)) throw new ArgumentException("Value cannot be null or empty.", "userName");
                if (String.IsNullOrEmpty(password)) throw new ArgumentException("Value cannot be null or empty.", "password");

                bool authenticated;
                var adHelper = new ActiveDirectoryHelper();

                authenticated = adHelper.ValidateUser(username, password);

                if (authenticated == false && username == "admin")
                {
                    var user = database.User.FirstOrDefault(i => i.Username == username);
                    authenticated = (user != null && ComparePassword(password, user.Password));

                }
                return authenticated;
            }
        }

        public bool CreateUser(string username, string password, string name, string surname, string email)
        {
            if (String.IsNullOrEmpty(username)) throw new ArgumentException("Value cannot be null or empty.", "userName");
            if (String.IsNullOrEmpty(password)) throw new ArgumentException("Value cannot be null or empty.", "password");
            if (String.IsNullOrEmpty(name)) throw new ArgumentException("Value cannot be null or empty.", "name");
            if (String.IsNullOrEmpty(surname)) throw new ArgumentException("Value cannot be null or empty.", "surname");
            if (String.IsNullOrEmpty(email)) throw new ArgumentException("Value cannot be null or empty.", "email");

            using (var database = new DataEntities())
            {
                var user = new User
                {
                    Username = username,
                    Password = EncryptPassword(password),
                    Name = name,
                    Surname = surname,
                    Email = email,
                };
                database.AddToUser(user);
                try
                {
                    database.SaveChanges();
                }
                catch (UpdateException)
                {
                    return false;
                }
            }

            return true;
        }

        public IList<UserModel> GetAllUsers()
        {
            var adHelper = new ActiveDirectoryHelper();
            var ldapUsers = adHelper.GetAllUsers();
            using (var db = new DataEntities())
            {
                var result = new List<UserModel>();

                var dbUsers = db.User;
                foreach (var user in ldapUsers)
                {
                    var foundUser = dbUsers.Where(x => x.Username == user.Username).FirstOrDefault();
                    if (foundUser == null)
                    {
                        CreateUserFromAdRecord(user);
                    }
                }

                foreach (var item in db.User)
                {
                    result.Add(new UserModel
                    {
                        Username = item.Username,
                        Name = item.Name,
                        Surname = item.Surname,
                        Email = item.Email,
                        Roles = item.Roles.Select(i => i.Name).ToArray(),
                    });
                }
                return result;
            }
        }

        public UserModel GetUser(string username)
        {
            if (String.IsNullOrEmpty(username)) throw new ArgumentException("Value cannot be null or empty.", "userName");

            using (var db = new DataEntities())
            {
                var user = db.User.FirstOrDefault(i => i.Username == username);
                return user == null ? null : new UserModel
                {
                    Username = user.Username,
                    Name = user.Name,
                    Surname = user.Surname,
                    Email = user.Email,
                    Roles = user.Roles.Select(i => i.Name).ToArray(),
                };
            }
        }

        public void UpdateUser(string username, string name, string surname, string email, string password)
        {
            using (var database = new DataEntities())
            {
                var user = database.User.FirstOrDefault(i => i.Username == username);
                if (user != null)
                {
                    user.Name = name ?? user.Name;
                    user.Surname = surname ?? user.Surname;
                    user.Email = email ?? user.Email;
                    user.Password = password != null ? EncryptPassword(password) : user.Password;
                    database.SaveChanges();
                }
            }
        }

        public void DeleteUser(string username)
        {
            using (var database = new DataEntities())
            {
                var user = database.User.FirstOrDefault(i => i.Username == username);
                if (user != null)
                {
                    user.AdministratedRepositories.Clear();
                    user.Roles.Clear();
                    user.Repositories.Clear();
                    user.Teams.Clear();
                    database.DeleteObject(user);
                    database.SaveChanges();
                }
            }
        }

        private bool ComparePassword(string password, string hash)
        {
            return EncryptPassword(password) == hash;
        }

        private string EncryptPassword(string password)
        {
            System.Security.Cryptography.MD5CryptoServiceProvider x = new System.Security.Cryptography.MD5CryptoServiceProvider();
            byte[] data = System.Text.Encoding.ASCII.GetBytes(password);
            data = x.ComputeHash(data);
            return System.Text.Encoding.ASCII.GetString(data);
        }

        private void CreateUserFromAdRecord(DirectoryEntry entry)
        {
            try
            {
                string email = entry.Properties["mail"].Value.ToString();
                string givenName = entry.Properties["givenName"].Value.ToString();
                string sn = entry.Properties["sn"].Value.ToString();
                CreateUser(email, email, givenName, sn, email);
            }
            catch (Exception ex)
            {
            }
        }
    }
}